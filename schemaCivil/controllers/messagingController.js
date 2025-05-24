const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const messagingSchema = require('../schema/messaging.schema.json');
const validate = ajv.compile(messagingSchema);
const { v4: uuidv4 } = require('uuid');

class MessagingController {
  constructor(messagingModel, chainAdapter, exchangeController) {
    this.messagingModel = messagingModel;
    this.chainAdapter = chainAdapter;
    this.exchangeController = exchangeController;
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a messaging platform
  async createPlatform(data) {
    this.validateData(data);
    const platform = await this.messagingModel.createPlatform(data);
    return { id: platform.id, title: platform.title };
  }

  // Get a platform by ID
  async getPlatform(platformId) {
    const platform = await this.messagingModel.getPlatform(platformId);
    return platform;
  }

  // Start a conversation
  async startConversation(platformId, creator, soulboundId, participantData) {
    const { participants, soulboundIds, messageType, groupId } = participantData;
    if (!participants.includes(creator)) {
      throw new Error('Creator must be a participant');
    }

    const reputation = await this.chainAdapter.getReputation(creator);
    if (reputation < 10) { // Example threshold
      throw new Error('Insufficient reputation to start conversation');
    }

    const conversationData = {
      id: uuidv4(),
      participants,
      soulboundIds,
      messageType: messageType || 'direct',
      groupId,
      messages: []
    };

    const conversation = await this.messagingModel.createConversation(platformId, conversationData);
    this.exchangeController.logComplianceEvent('conversation_started', creator, JSON.stringify({ platformId, conversationId: conversation.id }));
    return { id: conversation.id };
  }

  // Send a message
  async sendMessage(platformId, conversationId, sender, soulboundId, contentData) {
    const messageData = {
      id: uuidv4(),
      sender,
      soulboundId,
      content: {
        encryptionType: contentData.encryptionType || 'hybrid',
        data: contentData.data
      }
    };

    const message = await this.messagingModel.sendMessage(platformId, conversationId, messageData);
    return { id: message.id, timestamp: message.timestamp };
  }

  // Create a group
  async createGroup(platformId, creator, soulboundId, groupData) {
    const { members, soulboundIds, title } = groupData;
    if (!members.includes(creator)) {
      throw new Error('Creator must be a member');
    }

    const reputation = await this.chainAdapter.getReputation(creator);
    if (reputation < 20) { // Example threshold
      throw new Error('Insufficient reputation to create group');
    }

    const group = await this.messagingModel.createGroup(platformId, {
      id: uuidv4(),
      creator,
      soulboundId,
      members,
      soulboundIds,
      title
    });

    return { id: group.id, title: group.title };
  }

  // Update message status
  async updateMessageStatus(platformId, conversationId, messageId, recipient, soulboundId, status) {
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(recipient, soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for recipient ${recipient}`);
    }

    const message = await this.messagingModel.updateMessageStatus(platformId, conversationId, messageId, recipient, status);
    return { id: message.id, status: message.status };
  }

  // Rotate encryption keys
  async rotateEncryptionKeys(platformId, agent, soulboundId) {
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(agent, soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for agent ${agent}`);
    }

    const reputation = await this.chainAdapter.getReputation(agent);
    if (reputation < 50) { // Example threshold
      throw new Error('Insufficient reputation to rotate keys');
    }

    const result = await this.messagingModel.rotateEncryptionKeys(platformId);
    this.exchangeController.logComplianceEvent('keys_rotated', agent, JSON.stringify({ platformId }));
    return result;
  }

  // Propose a governance change
  async proposeGovernanceChange(platformId, agent, soulboundId, proposalData) {
    const platform = await this.messagingModel.getPlatform(platformId);
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(agent, soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for agent ${agent}`);
    }

    const reputation = await this.chainAdapter.getReputation(agent);
    if (reputation < platform.platform.governance.proposalThreshold) {
      throw new Error('Insufficient reputation to submit proposal');
    }

    const proposalId = proposalData.id || uuidv4();
    const proposal = {
      ...proposalData,
      id: proposalId,
      proposer: agent,
      createdAt: new Date().toISOString(),
      status: 'pending'
    };

    await this.chainAdapter.submitProposal(platform.platform.governance.votingContract, proposal);
    await this.chainAdapter.distributeKarmaWage(agent, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(agent, 0.7); // Example: +0.7 for proposal
    this.exchangeController.logComplianceEvent('proposal_submitted', agent, JSON.stringify({ platformId, proposalId }));
    return { proposal_id: proposalId };
  }
}

module.exports = MessagingController;