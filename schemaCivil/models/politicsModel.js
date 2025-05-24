const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const politicsSchema = require('../schema/politics.schema.json');
const validate = ajv.compile(politicsSchema);
const { v4: uuidv4 } = require('uuid');

class PoliticsModel {
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

  // Create a political platform
  async createPlatform(data) {
    this.validateData(data);
    const platformId = data.id || uuidv4();
    const platform = { ...data, id: platformId, type: 'politics', createdAt: new Date().toISOString() };

    // Verify soulbound IDs for petitions
    for (const petition of platform.platform.petitions) {
      const isValidSoulbound = await this.chainAdapter.verifySoulboundId(petition.creator, petition.soulboundId);
      if (!isValidSoulbound) {
        throw new Error(`Invalid soulbound ID for creator ${petition.creator}`);
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

  // Create a petition
  async createPetition(platformId, petitionData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    this.validateData({ platform: { petitions: [petitionData] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(petitionData.creator, petitionData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for creator ${petitionData.creator}`);
    }

    const petitionId = petitionData.id || uuidv4();
    const petition = {
      ...petitionData,
      id: petitionId,
      status: 'open',
      signatures: [],
      createdAt: new Date().toISOString(),
      expiry: petitionData.expiry || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30-day default
    };

    platform.platform.petitions.push(petition);

    // Trigger onPetitionCreate hook
    if (platform.platform.transactionHooks?.onPetitionCreate) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onPetitionCreate, { platformId, petitionId });
    }

    await this.chainAdapter.registerPetition(platformId, petition);
    await this.chainAdapter.distributeKarmaWage(petition.creator, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(petition.creator, 0.7); // Example: +0.7 for petition
    this.exchangeController.logComplianceEvent('petition_created', petition.creator, JSON.stringify({ platformId, petitionId, title: petition.title }));
    return petition;
  }

  // Sign a petition
  async signPetition(platformId, petitionId, agent, soulboundId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const petition = platform.platform.petitions.find(p => p.id === petitionId);
    if (!petition || petition.status !== 'open') {
      throw new Error('Petition not found or closed');
    }

    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(agent, soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for agent ${agent}`);
    }

    if (petition.signatures.some(s => s.agent === agent)) {
      throw new Error('Agent already signed petition');
    }

    const signature = {
      agent,
      soulboundId,
      timestamp: new Date().toISOString()
    };
    petition.signatures.push(signature);

    // Check if threshold reached
    if (petition.threshold && petition.signatures.length >= petition.threshold) {
      petition.status = 'escalated';
      await this.createProposalFromPetition(platformId, petitionId);
    }

    await this.chainAdapter.updatePetition(platformId, petition);
    await this.chainAdapter.distributeKarmaWage(agent, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(agent, 0.3); // Example: +0.3 for signing
    this.exchangeController.logComplianceEvent('petition_signed', agent, JSON.stringify({ platformId, petitionId }));
    return signature;
  }

  // Create a proposal from a petition
  async createProposalFromPetition(platformId, petitionId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const petition = platform.platform.petitions.find(p => p.id === petitionId);
    if (!petition || petition.status !== 'escalated') {
      throw new Error('Petition not found or not escalated');
    }

    const proposalId = uuidv4();
    const proposal = {
      id: proposalId,
      creator: petition.creator,
      soulboundId: petition.soulboundId,
      title: `Proposal: ${petition.title}`,
      description: petition.description,
      actionType: petition.actionType,
      actionDetails: petition.actionDetails,
      votes: [],
      status: 'pending',
      createdAt: new Date().toISOString(),
      expiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7-day voting period
    };

    platform.platform.proposals.push(proposal);

    // Trigger onProposalSubmit hook
    if (platform.platform.transactionHooks?.onProposalSubmit) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onProposalSubmit, { platformId, proposalId });
    }

    await this.chainAdapter.registerProposal(platformId, proposal);
    this.exchangeController.logComplianceEvent('proposal_created', petition.creator, JSON.stringify({ platformId, proposalId, title: proposal.title }));
    return proposal;
  }

  // Vote on a proposal
  async voteOnProposal(platformId, proposalId, agent, soulboundId, vote) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const proposal = platform.platform.proposals.find(p => p.id === proposalId);
    if (!proposal || proposal.status !== 'pending') {
      throw new Error('Proposal not found or not open for voting');
    }

    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(agent, soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for agent ${agent}`);
    }

    if (proposal.votes.some(v => v.agent === agent)) {
      throw new Error('Agent already voted');
    }

    const reputation = await this.chainAdapter.getReputation(agent);
    if (reputation < platform.platform.governance.proposalThreshold) {
      throw new Error('Insufficient reputation to vote');
    }

    const voteRecord = {
      agent,
      soulboundId,
      vote,
      timestamp: new Date().toISOString()
    };
    proposal.votes.push(voteRecord);

    // Trigger onVote hook
    if (platform.platform.transactionHooks?.onVote) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onVote, { platformId, proposalId, vote });
    }

    await this.chainAdapter.updateProposal(platformId, proposal);
    await this.chainAdapter.distributeKarmaWage(agent, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(agent, 0.5); // Example: +0.5 for voting
    this.exchangeController.logComplianceEvent('proposal_voted', agent, JSON.stringify({ platformId, proposalId, vote }));
    return voteRecord;
  }

  // Resolve a dispute
  async resolveDispute(platformId, disputeData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    this.validateData({ platform: { disputes: [disputeData] } });
    const disputeId = disputeData.id || uuidv4();
    const dispute = {
      ...disputeData,
      id: disputeId,
      status: 'open',
      createdAt: new Date().toISOString()
    };

    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(dispute.creator, dispute.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for creator ${dispute.creator}`);
    }

    platform.platform.disputes.push(dispute);

    // Trigger onDispute hook
    if (platform.platform.transactionHooks?.onDispute) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onDispute, { platformId, disputeId });
    }

    // Resolve dispute based on governance method
    if (platform.platform.governance.disputeResolution === 'voting') {
      const voteResult = await this.chainAdapter.submitDisputeVote(platform.platform.governance.votingContract, dispute);
      dispute.status = voteResult.approved ? 'resolved' : 'dismissed';
      dispute.resolution = { method: 'voting', outcome: voteResult.outcome };
      if (voteResult.approved) {
        await this.chainAdapter.updateReputation(dispute.target, -1); // Example: -1 for valid dispute
      }
    }

    await this.chainAdapter.updateDispute(platformId, dispute);
    await this.chainAdapter.distributeKarmaWage(dispute.creator, platform.platform.karmaWage);
    this.exchangeController.logComplianceEvent('dispute_created', dispute.creator, JSON.stringify({ platformId, disputeId, target: dispute.target }));
    return dispute;
  }

  // Check for expired petitions and proposals
  async checkExpirations(platformId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const now = new Date();
    for (const petition of platform.platform.petitions) {
      if (petition.expiry && new Date(petition.expiry) < now && petition.status === 'open') {
        petition.status = 'closed';
        await this.chainAdapter.updatePetition(platformId, petition);
        this.exchangeController.logComplianceEvent('petition_expired', 'system', JSON.stringify({ platformId, petitionId: petition.id }));
      }
    }

    for (const proposal of platform.platform.proposals) {
      if (proposal.expiry && new Date(proposal.expiry) < now && proposal.status === 'pending') {
        proposal.status = 'rejected';
        await this.chainAdapter.updateProposal(platformId, proposal);
        this.exchangeController.logComplianceEvent('proposal_expired', 'system', JSON.stringify({ platformId, proposalId: proposal.id }));
      }
    }
  }
}

module.exports = PoliticsModel;