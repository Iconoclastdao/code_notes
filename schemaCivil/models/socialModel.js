const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const socialSchema = require('../schema/social.schema.json');
const validate = ajv.compile(socialSchema);
const { v4: uuidv4 } = require('uuid');

class SocialModel {
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

  // Create a social platform
  async createPlatform(data) {
    this.validateData(data);
    const platformId = data.id || uuidv4();
    const platform = { ...data, id: platformId, type: 'social', createdAt: new Date().toISOString() };

    // Verify soulbound IDs for posts and groups
    for (const post of platform.platform.posts || []) {
      const isValidSoulbound = await this.chainAdapter.verifySoulboundId(post.creator, post.soulboundId);
      if (!isValidSoulbound) {
        throw new Error(`Invalid soulbound ID for creator ${post.creator}`);
      }
    }
    for (const group of platform.platform.groups || []) {
      const isValidSoulbound = await this.chainAdapter.verifySoulboundId(group.creator, group.soulboundId);
      if (!isValidSoulbound) {
        throw new Error(`Invalid soulbound ID for creator ${group.creator}`);
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

  // Create a post
  async createPost(platformId, postData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    this.validateData({ platform: { posts: [postData] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(postData.creator, postData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for creator ${postData.creator}`);
    }

    const reputation = await this.chainAdapter.getReputation(postData.creator);
    if (reputation < platform.platform.governance.proposalThreshold / 2) {
      throw new Error('Insufficient reputation to create post');
    }

    // Verify group for group posts
    if (postData.visibility === 'group') {
      const group = platform.platform.groups.find(g => g.id === postData.groupId);
      if (!group || !group.members.includes(postData.creator)) {
        throw new Error('Group not found or creator not a member');
      }
    }

    const postId = postData.id || uuidv4();
    const post = {
      ...postData,
      id: postId,
      status: 'active',
      comments: [],
      reactions: [],
      createdAt: new Date().toISOString(),
      expiry: postData.expiry || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30-day default
    };

    platform.platform.posts.push(post);

    // Trigger onPostCreate hook
    if (platform.platform.transactionHooks?.onPostCreate) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onPostCreate, { platformId, postId });
    }

    await this.chainAdapter.registerPost(platformId, post);
    await this.chainAdapter.distributeKarmaWage(post.creator, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(post.creator, 0.5); // Example: +0.5 for posting
    this.exchangeController.logComplianceEvent('post_created', post.creator, JSON.stringify({ platformId, postId, tags: post.tags }));
    return post;
  }

  // Add a comment
  async addComment(platformId, postId, commentData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const post = platform.platform.posts.find(p => p.id === postId);
    if (!post || post.status !== 'active') {
      throw new Error('Post not found or not active');
    }

    this.validateData({ platform: { posts: [{ comments: [commentData] }] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(commentData.creator, commentData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for creator ${commentData.creator}`);
    }

    const reputation = await this.chainAdapter.getReputation(commentData.creator);
    if (reputation < platform.platform.governance.proposalThreshold / 4) {
      throw new Error('Insufficient reputation to comment');
    }

    const commentId = commentData.id || uuidv4();
    const comment = {
      ...commentData,
      id: commentId,
      createdAt: new Date().toISOString()
    };

    post.comments.push(comment);

    // Trigger onComment hook
    if (platform.platform.transactionHooks?.onComment) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onComment, { platformId, postId, commentId });
    }

    await this.chainAdapter.updatePost(platformId, post);
    await this.chainAdapter.distributeKarmaWage(comment.creator, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(commentData.creator, 0.3); // Example: +0.3 for commenting
    this.exchangeController.logComplianceEvent('comment_added', comment.creator, JSON.stringify({ platformId, postId, commentId }));
    return comment;
  }

  // Add a reaction
  async addReaction(platformId, postId, reactionData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const post = platform.platform.posts.find(p => p.id === postId);
    if (!post || post.status !== 'active') {
      throw new Error('Post not found or not active');
    }

    this.validateData({ platform: { posts: [{ reactions: [reactionData] }] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(reactionData.agent, reactionData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for agent ${reactionData.agent}`);
    }

    if (post.reactions.some(r => r.agent === reactionData.agent && r.type === reactionData.type)) {
      throw new Error('Reaction already exists');
    }

    const reaction = {
      ...reactionData,
      timestamp: new Date().toISOString()
    };

    post.reactions.push(reaction);

    // Trigger onReaction hook
    if (platform.platform.transactionHooks?.onReaction) {
      await this.chainAdapter.executeHook(platform.platform.transactionHooks.onReaction, { platformId, postId, reactionType: reaction.type });
    }

    await this.chainAdapter.updatePost(platformId, post);
    await this.chainAdapter.distributeKarmaWage(reaction.agent, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(reaction.agent, 0.1); // Example: +0.1 for reacting
    this.exchangeController.logComplianceEvent('reaction_added', reaction.agent, JSON.stringify({ platformId, postId, reactionType: reaction.type }));

    // Handle flagging for moderation
    if (reaction.type === 'flag') {
      const flagCount = post.reactions.filter(r => r.type === 'flag').length;
      if (flagCount >= platform.platform.governance.moderationThreshold || 5) {
        post.status = 'moderated';
        await this.initiateModeration(platformId, postId, reaction.agent);
      }
    }

    return reaction;
  }

  // Create a group
  async createGroup(platformId, groupData) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    this.validateData({ platform: { groups: [groupData] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(groupData.creator, groupData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for creator ${groupData.creator}`);
    }

    const reputation = await this.chainAdapter.getReputation(groupData.creator);
    if (reputation < platform.platform.governance.proposalThreshold) {
      throw new Error('Insufficient reputation to create group');
    }

    const groupId = groupData.id || uuidv4();
    const group = {
      ...groupData,
      id: groupId,
      createdAt: new Date().toISOString()
    };

    platform.platform.groups.push(group);
    await this.chainAdapter.registerGroup(platformId, group);
    await this.chainAdapter.distributeKarmaWage(group.creator, platform.platform.karmaWage);
    await this.chainAdapter.updateReputation(group.creator, 0.5); // Example: +0.5 for group creation
    this.exchangeController.logComplianceEvent('group_created', group.creator, JSON.stringify({ platformId, groupId, title: group.title }));
    return group;
  }

  // Initiate moderation for a post
  async initiateModeration(platformId, postId, initiator) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const post = platform.platform.posts.find(p => p.id === postId);
    if (!post) {
      throw new Error('Post not found');
    }

    if (platform.platform.governance.disputeResolution === 'voting') {
      const disputeId = uuidv4();
      const dispute = {
        id: disputeId,
        creator: initiator,
        target: postId,
        reason: 'Content flagged for moderation',
        status: 'open',
        createdAt: new Date().toISOString()
      };

      platform.platform.disputes = platform.platform.disputes || [];
      platform.platform.disputes.push(dispute);

      const voteResult = await this.chainAdapter.submitDisputeVote(platform.platform.governance.votingContract, dispute);
      dispute.status = voteResult.approved ? 'resolved' : 'dismissed';
      dispute.resolution = { method: 'voting', outcome: voteResult.outcome };

      if (voteResult.approved) {
        post.status = 'removed';
        await this.chainAdapter.updateReputation(post.creator, -1); // Example: -1 for removed post
      } else {
        post.status = 'active';
      }

      await this.chainAdapter.updateDispute(platformId, dispute);
      await this.chainAdapter.updatePost(platformId, post);
      this.exchangeController.logComplianceEvent('moderation_completed', initiator, JSON.stringify({ platformId, postId, disputeId, outcome: dispute.status }));
    }

    return { postId, status: post.status };
  }

  // Check for expired posts
  async checkExpirations(platformId) {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error('Platform not found');
    }

    const now = new Date();
    for (const post of platform.platform.posts) {
      if (post.expiry && new Date(post.expiry) < now && post.status === 'active') {
        post.status = 'expired';
        await this.chainAdapter.updatePost(platformId, post);
        this.exchangeController.logComplianceEvent('post_expired', 'system', JSON.stringify({ platformId, postId: post.id }));
      }
    }
  }
}

module.exports = SocialModel;