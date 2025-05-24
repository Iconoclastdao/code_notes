const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const datingSchema = require('../schema/dating.schema.json');
const validate = ajv.compile(datingSchema);
const { v4: uuidv4 } = require('uuid');

class DatingModel {
  constructor(chainAdapter, exchangeController) {
    this.chainAdapter = chainAdapter;
    this.exchangeController = exchangeController;
    this.platforms = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a dating platform
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
    return platform;
  }

  // Get a platform by ID
  getPlatform(platformId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }
    return platform;
  }

  // Add a profile
  async addProfile(platformId, profileData) {
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
    await this.chainAdapter.registerProfile(platformId, profile);
    this.exchangeController.logComplianceEvent('profile_created', profile.agent, JSON.stringify({ platformId, profileId, displayName: profile.displayName }));
    return profile;
  }

  // Create a match
  async createMatch(platformId, matchData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const { agent1, agent2, compatibilityScore } = matchData;
    const profile1 = platform.platform.profiles.find(p => p.agent === agent1 && p.verified);
    const profile2 = platform.platform.profiles.find(p => p.agent === agent2 && p.verified);
    if (!profile1 || !profile2) {
      throw new Error('One or both profiles not found or unverified');
    }

    const matchId = matchData.id || uuidv4();
    const match = {
      id: matchId,
      agent1,
      agent2,
      status: 'pending',
      compatibilityScore: Math.min(Math.max(compatibilityScore, 0), 100),
      createdAt: new Date().toISOString(),
      expiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    };

    platform.platform.matches.push(match);
    await this.chainAdapter.registerMatch(platformId, match);
    this.exchangeController.logComplianceEvent('match_created', 'system', JSON.stringify({ platformId, matchId, agent1, agent2 }));
    return match;
  }
}

module.exports = DatingModel;