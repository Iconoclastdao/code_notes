const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const datingSchema = require('../schema/dating.schema.json');
const validate = ajv.compile(datingSchema);
const { v4: uuidv4 } = require('uuid');

class DatingController {
  constructor(exchangeController, chainAdapter) {
    this.exchangeController = exchangeController;
    this.chainAdapter = chainAdapter;
    this.platforms = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a new dating platform
  async createPlatform(data) {
    this.validateData(data);
    const platformId = data.id || uuidv4();
    const platform = { ...data, id: platformId, type: 'dating', createdAt: new Date().toISOString() };

    // Verify soulbound IDs for profiles
    for (const profile of platform.platform.profiles) {
      const isValidSoulbound = await this.chainAdapter.verifySoulboundId(profile.agent, profile.soulboundId);
      if (!isValidSoulbound) {
        throw new Error(`Invalid soulbound ID for agent ${profile.agent}`);
      }
    }

    this.platforms.set(platformId, platform);
    await this.chainAdapter.registerPlatform(platformId, platform);
    this.exchangeController.logComplianceEvent('platform_created', 'system', JSON.stringify({ id: platformId, title: platform.title }));
    return { id: platformId };
  }

  // Get a platform by ID
  getPlatform(platformId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }
    return platform;
  }

  // Create a new profile
  async createProfile(platformId, profileData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }
    if (!platform.platform.allowUserProfiles) {
      throw new Error('User profiles not allowed');
    }

    this.validateData({ platform: { profiles: [profileData] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(profileData.agent, profileData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for agent ${profileData.agent}`);
    }

    const profileId = profileData.id || uuidv4();
    const profile = {
      ...profileData,
      id: profileId,
      createdAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString()
    };
    platform.platform.profiles.push(profile);

    // Distribute karma wage for profile creation
    await this.chainAdapter.distributeKarmaWage(profile.agent, platform.platform.karmaWage);
    await this.chainAdapter.registerProfile(platformId, profile);
    this.exchangeController.logComplianceEvent('profile_created', profile.agent, JSON.stringify({ platformId, profileId, displayName: profile.displayName }));
    return { id: profileId };
  }

  // Verify a profile
  async verifyProfile(platformId, profileId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const profile = platform.platform.profiles.find(p => p.id === profileId);
    if (!profile) {
      throw new Error('Profile not found');
    }

    // Trigger onVerify hook
    if (platform.platform.transactionHooks?.onVerify) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onVerify, { platformId, profileId });
    }

    profile.verified = true;
    profile.lastUpdated = new Date().toISOString();
    await this.chainAdapter.updateProfile(platformId, profile);
    this.exchangeController.logComplianceEvent('profile_verified', 'system', JSON.stringify({ platformId, profileId }));
    return { message: 'Profile verified' };
  }

  // Create a match
  async createMatch(platformId, agent1, agent2, compatibilityScore) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const profile1 = platform.platform.profiles.find(p => p.agent === agent1 && p.verified);
    const profile2 = platform.platform.profiles.find(p => p.agent === agent2 && p.verified);
    if (!profile1 || !profile2) {
      throw new Error('One or both profiles not found or unverified');
    }

    const matchId = uuidv4();
    const match = {
      id: matchId,
      agent1,
      agent2,
      status: 'pending',
      compatibilityScore: Math.min(Math.max(compatibilityScore, 0), 100),
      createdAt: new Date().toISOString(),
      expiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7-day expiry
    };

    platform.platform.matches.push(match);

    // Trigger onMatch hook
    if (platform.platform.transactionHooks?.onMatch) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onMatch, { platformId, matchId });
    }

    // Distribute karma wage for match
    await this.chainAdapter.distributeKarmaWage(agent1, platform.platform.karmaWage);
    await this.chainAdapter.distributeKarmaWage(agent2, platform.platform.karmaWage);
    await this.chainAdapter.registerMatch(platformId, match);
    this.exchangeController.logComplianceEvent('match_created', 'system', JSON.stringify({ platformId, matchId, agent1, agent2 }));
    return { id: matchId };
  }

  // Accept or reject a match
  async updateMatchStatus(platformId, matchId, agentId, status) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const match = platform.platform.matches.find(m => m.id === matchId);
    if (!match || (match.agent1 !== agentId && match.agent2 !== agentId)) {
      throw new Error('Match not found or agent not authorized');
    }

    if (!['accepted', 'rejected'].includes(status)) {
      throw new Error('Invalid status');
    }

    match.status = status;
    match.lastUpdated = new Date().toISOString();
    await this.chainAdapter.updateMatch(platformId, match);

    if (status === 'accepted') {
      await this.chainAdapter.updateReputation(agentId, 1); // +1 for successful match
      await this.chainAdapter.distributeKarmaWage(agentId, platform.platform.karmaWage);
    }

    this.exchangeController.logComplianceEvent('match_updated', agentId, JSON.stringify({ platformId, matchId, status }));
    return { message: `Match ${status}` };
  }

  // Create an interaction (e.g., message, session)
  async createInteraction(platformId, interactionData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    this.validateData({ platform: { interactions: [interactionData] } });
    const { agent1, agent2 } = interactionData;
    const match = platform.platform.matches.find(m => 
      (m.agent1 === agent1 && m.agent2 === agent2 || m.agent1 === agent2 && m.agent2 === agent1) && 
      m.status === 'accepted'
    );
    if (!match) {
      throw new Error('No accepted match found for interaction');
    }

    const interactionId = interactionData.id || uuidv4();
    const interaction = {
      ...interactionData,
      id: interactionId,
      createdAt: new Date().toISOString()
    };
    platform.platform.interactions.push(interaction);

    // Trigger onInteract hook
    if (platform.platform.transactionHooks?.onInteract) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onInteract, { platformId, interactionId });
    }

    // Distribute karma wage for interaction
    await this.chainAdapter.distributeKarmaWage(agent1, platform.platform.karmaWage);
    await this.chainAdapter.registerInteraction(platformId, interaction);
    this.exchangeController.logComplianceEvent('interaction_created', agent1, JSON.stringify({ platformId, interactionId, type: interaction.type }));
    return { id: interactionId };
  }

  // Resolve a dispute
  async resolveDispute(platformId, disputeData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const { agentId, targetId, reason } = disputeData;
    const profile = platform.platform.profiles.find(p => p.agent === agentId && p.verified);
    if (!profile) {
      throw new Error('Agent profile not found or unverified');
    }

    // Trigger onDispute hook
    if (platform.platform.transactionHooks?.onDispute) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onDispute, { platformId, agentId, targetId, reason });
    }

    // Example: Lower reputation of target if dispute is valid (via governance)
    if (platform.platform.governance.disputeResolution === 'voting') {
      const voteResult = await this.chainAdapter.submitDisputeVote(platform.platform.governance.votingContract, { agentId, targetId, reason });
      if (voteResult.approved) {
        await this.chainAdapter.updateReputation(targetId, -1); // Example: -1 for dispute
      }
    }

    this.exchangeController.logComplianceEvent('dispute_resolved', agentId, JSON.stringify({ platformId, targetId, reason }));
    return { message: 'Dispute resolved' };
  }

  // Check for expired matches
  async checkExpiredMatches(platformId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const now = new Date();
    for (const match of platform.platform.matches) {
      if (match.expiry && new Date(match.expiry) < now && match.status !== 'expired') {
        match.status = 'expired';
        match.lastUpdated = new Date().toISOString();
        await this.chainAdapter.updateMatch(platformId, match);
        this.exchangeController.logComplianceEvent('match_expired', 'system', JSON.stringify({ platformId, matchId: match.id }));
      }
    }
  }
}

module.exports = DatingController;