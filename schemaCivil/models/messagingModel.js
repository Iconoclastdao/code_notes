const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const messagingSchema = require('../schema/messaging.schema.json');
const validate = ajv.compile(messagingSchema);
const { v4: uuidv4 } = require('uuid');

class MessagingModel {
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

  // Create a messaging platform
  async createPlatform(data) {
    this.validateData(data);
    const platformId = data.id || uuidv4();
    const platform = { ...data, id: platformId, type: 'messaging', createdAt: new Date().toISOString() };

    // Verify soulbound IDs for conversations and groups
    for (const conversation of platform.platform.conversations) {
      for (let i = 0; i < conversation.participants.length; i++) {
        const isValidSoulbound = await this.chainAdapter.verifySoulboundId(
          conversation.participants[i],
          conversation.soulboundIds[i]
        );
        if (!isValidSoulbound) {
          throw new Error(`Invalid soulbound ID for participant ${conversation.participants[i]}`);
        }
      }
    }
    for (const group of platform.platform.groups) {
      for (let i = 0; i < group.members.length; i++) {
        const isValidSoulbound = await this.chainAdapter.verifySoulboundId(
          group.members[i],
          group.soulboundIds[i]
        );
        if (!isValidSoulbound) {
          throw new Error(`Invalid soulbound ID for member ${group.members[i]}`);
        }
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

  // Create a conversation
  async createConversation(platformId, conversationData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    this.validateData({ platform: { conversations: [conversationData] } });
    for (let i = 0; i < conversationData.participants.length; i++) {
      const isValidSoulbound = await this.chainAdapter.verifySoulboundId(
        conversationData.participants[i],
        conversationData.soulboundIds[i]
      );
      if (!isValidSoulbound) {
        throw new Error(`Invalid soulbound ID for participant ${conversationData.participants[i]}`);
      }
    }

    // Verify group for group conversations
    if (conversationData.messageType === 'group') {
      const group = platform.platform.groups.find(g => g.id === conversationData.groupId);
      if (!group || !group.members.every(m => conversationData.participants.includes(m))) {
        throw new Error('Group not found or invalid participants');
      }
    }

    const conversationId = conversationData.id || uuidv4();
    const conversation = {
      ...conversationData,
      id: conversationId,
      messages: [],
      createdAt: new Date().toISOString()
    };

    platform.platform.conversations.push(conversation);

    // Trigger onConversationStart hook
    if (platform.platform.transactionHooks?.onConversationStart) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onConversationStart, { platformId, conversationId });
    }

    await this.chainAdapter.registerConversation(platformId, conversation);
    await this.chainAdapter.distributeKarmaWage(conversation.participants[0], platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(conversation.participants[0], 0.3); // Example: +0.3 for conversation
    this.exchangeController.logComplianceEvent('conversation_created', conversation.participants[0], JSON.stringify({ platformId, conversationId }));
    return conversation;
  }

  // Send a message
  async sendMessage(platformId, conversationId, messageData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const conversation = platform.platform.conversations.find(c => c.id === conversationId);
    if (!conversation || !conversation.participants.includes(messageData.sender)) {
      throw new Error('Conversation not found or sender not a participant');
    }

    this.validateData({ platform: { conversations: [{ messages: [messageData] }] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(messageData.sender, messageData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for sender ${messageData.sender}`);
    }

    const messageId = messageData.id || uuidv4();
    const message = {
      ...messageData,
      id: messageId,
      timestamp: new Date().toISOString(),
      status: 'sent',
      readBy: [],
      expiry: messageData.expiry || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30-day default
    };

    conversation.messages.push(message);

    // Trigger onMessageSend hook
    if (platform.platform.transactionHooks?.onMessageSend) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onMessageSend, { platformId, conversationId, messageId });
    }

    await this.chainAdapter.registerMessage(platformId, conversationId, message);
    await this.chainAdapter.distributeKarmaWage(message.sender, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(message.sender, 0.2); // Example: +0.2 for messaging
    this.exchangeController.logComplianceEvent('message_sent', message.sender, JSON.stringify({ platformId, conversationId, messageId }));
    return message;
  }

  // Create a group
  async createGroup(platformId, groupData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    this.validateData({ platform: { groups: [groupData] } });
    for (let i = 0; i < groupData.members.length; i++) {
      const isValidSoulbound = await this.chainAdapter.verifySoulboundId(groupData.members[i], groupData.soulboundIds[i]);
      if (!isValidSoulbound) {
        throw new Error(`Invalid soulbound ID for member ${groupData.members[i]}`);
      }
    }

    const groupId = groupData.id || uuidv4();
    const group = {
      ...groupData,
      id: groupId,
      createdAt: new Date().toISOString()
    };

    platform.platform.groups.push(group);

    // Trigger onGroupCreate hook
    if (platform.platform.transactionHooks?.onGroupCreate) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onGroupCreate, { platformId, groupId });
    }

    await this.chainAdapter.registerGroup(platformId, group);
    await this.chainAdapter.distributeKarmaWage(group.creator, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(group.creator, 0.5); // Example: +0.5 for group creation
    this.exchangeController.logComplianceEvent('group_created', group.creator, JSON.stringify({ platformId, groupId, title: group.title }));
    return group;
  }

  // Update message status
  async updateMessageStatus(platformId, conversationId, messageId, recipient, status) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const conversation = platform.platform.conversations.find(c => c.id === conversationId);
    if (!conversation || !conversation.participants.includes(recipient)) {
      throw new Error('Conversation not found or recipient not a participant');
    }

    const message = conversation.messages.find(m => m.id === messageId);
    if (!message) {
      throw new Error('Message not found');
    }

    message.status = status;
    if (status === 'read' && !message.readBy.includes(recipient)) {
      message.readBy.push(recipient);
    }

    await this.chainAdapter.updateMessage(platformId, conversationId, message);
    this.exchangeController.logComplianceEvent('message_status_updated', recipient, JSON.stringify({ platformId, conversationId, messageId, status }));
    return message;
  }

  // Rotate encryption keys
  async rotateEncryptionKeys(platformId) {
    const platform = this.platforms.get(platformId);
    if (!platform || !platform.platform.encryption.enabled) {
      throw new Error('Platform not found or encryption disabled');
    }

    await this.chainAdapter.rotateKeys(platformId, platform.platform.encryption.algorithm);
    this.exchangeController.logComplianceEvent('keys_rotated', 'system', JSON.stringify({ platformId, algorithm: platform.platform.encryption.algorithm }));
    return { message: 'Encryption keys rotated successfully' };
  }
}

module.exports = MessagingModel;