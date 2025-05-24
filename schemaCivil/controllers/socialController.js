const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const socialSchema = require('../schema/social/social.schema.json');
const validate = ajv.compile(socialSchema);

class SocialController {
  constructor(exchangeController) {
    this.exchangeController = exchangeController;
    this.socialData = {
      profiles: [],
      posts: [],
      connections: []
    };
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    return valid;
  }

  createProfile(userId, username, bio = '') {
    const profile = {
      user: userId,
      username,
      bio,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      status: 'active'
    };
    this.socialData.profiles.push(profile);
    this.validateData(this.socialData);
    this.exchangeController.logComplianceEvent('profile_created', userId, JSON.stringify({ username }));
    return profile;
  }

  createPost(userId, content, visibility = 'public') {
    const post = {
      id: crypto.randomUUID(),
      user: userId,
      content,
      visibility,
      timestamp: new Date().toISOString(),
      likes: 0,
      comments: []
    };
    this.socialData.posts.push(post);
    this.validateData(this.socialData);
    this.exchangeController.logComplianceEvent('post_created', userId, JSON.stringify({ postId: post.id }));
    return post;
  }

  addConnection(userId, targetUserId) {
    const connection = {
      id: crypto.randomUUID(),
      user: userId,
      target: targetUserId,
      status: 'active',
      createdAt: new Date().toISOString()
    };
    this.socialData.connections.push(connection);
    this.validateData(this.socialData);
    this.exchangeController.logComplianceEvent('connection_added', userId, JSON.stringify({ target: targetUserId }));
    return connection;
  }

  getUserPosts(userId, visibility = 'public') {
    const posts = this.socialData.posts.filter(p => p.user === userId && p.visibility === visibility);
    this.validateData(this.socialData);
    return posts;
  }

  getSocialData() {
    return this.socialData;
  }
}

module.exports = SocialController;