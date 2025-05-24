const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const nodeSchema = require('../schema/nodes/sovereign-entropy-node.schema.json');
const validate = ajv.compile(nodeSchema);
const { v4: uuidv4 } = require('uuid');

class SovereignEntropyNodeController {
  constructor(exchangeController, chainAdapter) {
    this.exchangeController = exchangeController;
    this.chainAdapter = chainAdapter;
    this.nodes = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a new node
  async createNode(data) {
    this.validateData(data);
    const nodeId = data.node_id || uuidv4();
    const node = {
      ...data,
      node_id: nodeId,
      type: 'entropy-node',
      creation_date: new Date().toISOString(),
      reputation_score: data.reputation_score || 50
    };

    // Verify soulbound ID
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(node.wallet_address, node.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for wallet ${node.wallet_address}`);
    }

    this.nodes.set(nodeId, node);
    await this.chainAdapter.registerNode(nodeId, node);
    this.exchangeController.logComplianceEvent('node_created', node.wallet_address, JSON.stringify({ node_id: nodeId, username: node.username }));
    return { node_id: nodeId };
  }

  // Get a node by ID
  getNode(nodeId) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }
    return node;
  }

  // Fetch entropy from contract
  async fetchEntropy(nodeId, contractIndex = 0) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }

    const { contracts, method, format, cacheTTL, retryPolicy, postProcess } = node.entropy_agent;
    let entropy;
    let attempts = 0;

    // Retry logic
    while (attempts < retryPolicy.maxAttempts) {
      try {
        entropy = await this.chainAdapter.callContract(contracts[contractIndex], method, format);
        break;
      } catch (error) {
        attempts++;
        if (attempts >= retryPolicy.maxAttempts) {
          throw new Error(`Failed to fetch entropy after ${attempts} attempts: ${error.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, retryPolicy.backoffMs));
      }
    }

    // Post-process entropy if specified
    let processedEntropy = entropy;
    if (postProcess?.type !== 'none') {
      processedEntropy = await this.chainAdapter.executePostProcess(postProcess.type, postProcess.callback, entropy);
    }

    // Cache entropy
    await this.chainAdapter.cacheEntropy(nodeId, processedEntropy, cacheTTL);

    // Trigger onEntropyFetch hook
    if (node.transactionHooks?.onEntropyFetch) {
      await this.chainAdapter.executeHook(node.transactionHooks.onEntropyFetch, { nodeId, entropy: processedEntropy });
    }

    // Distribute karma wage
    await this.chainAdapter.distributeKarmaWage(node.wallet_address, node.karmaWage);
    await this.chainAdapter.updateReputation(node.wallet_address, 0.5); // Example: +0.5 for entropy fetch
    this.exchangeController.logComplianceEvent('entropy_fetched', node.wallet_address, JSON.stringify({ node_id: nodeId, contract: contracts[contractIndex] }));
    return { entropy: processedEntropy };
  }

  // Cast a governance vote
  async castVote(nodeId, proposalId, vote) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }
    if (!node.roles.includes('voter')) {
      throw new Error('Node not authorized to vote');
    }
    if (node.reputation_score < node.governance.proposalThreshold) {
      throw new Error('Insufficient reputation to vote');
    }

    await this.chainAdapter.submitVote(node.governance.votingContract, node.wallet_address, proposalId, vote);
    node.votes_cast += 1;

    // Trigger onVote hook
    if (node.transactionHooks?.onVote) {
      await this.chainAdapter.executeHook(node.transactionHooks.onVote, { nodeId, proposalId, vote });
    }

    // Distribute karma wage
    await this.chainAdapter.distributeKarmaWage(node.wallet_address, node.karmaWage);
    await this.chainAdapter.updateReputation(node.wallet_address, 0.3); // Example: +0.3 for voting
    this.exchangeController.logComplianceEvent('vote_cast', node.wallet_address, JSON.stringify({ node_id: nodeId, proposalId, vote }));
    return { message: 'Vote cast successfully' };
  }

  // Create a project
  async createProject(nodeId, projectData) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }
    if (!node.roles.includes('creator')) {
      throw new Error('Node not authorized to create projects');
    }

    const projectId = projectData.id || uuidv4();
    node.projects_owned = node.projects_owned || [];
    node.projects_owned.push(projectId);

    // Trigger onProjectCreate hook
    if (node.transactionHooks?.onProjectCreate) {
      await this.chainAdapter.executeHook(node.transactionHooks.onProjectCreate, { nodeId, projectId });
    }

    // Distribute karma wage
    await this.chainAdapter.distributeKarmaWage(node.wallet_address, node.karmaWage);
    await this.chainAdapter.updateReputation(node.wallet_address, 1); // Example: +1 for project creation
    this.exchangeController.logComplianceEvent('project_created', node.wallet_address, JSON.stringify({ node_id: nodeId, projectId }));
    return { project_id: projectId };
  }

  // Update staking balance
  async updateStakingBalance(nodeId, amount) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }

    if (amount < 0 && node.staking_balance + amount < 0) {
      throw new Error('Insufficient staking balance');
    }

    node.staking_balance += amount;
    await this.chainAdapter.updateStaking(node.wallet_address, node.staking_balance);
    this.exchangeController.logComplianceEvent('staking_updated', node.wallet_address, JSON.stringify({ node_id: nodeId, amount }));
    return { staking_balance: node.staking_balance };
  }

  // Toggle ad revenue opt-in
  async toggleAdRevenue(nodeId, optIn) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }

    node.ad_revenue_opt_in = optIn;
    this.exchangeController.logComplianceEvent('ad_revenue_toggled', node.wallet_address, JSON.stringify({ node_id: nodeId, optIn }));
    return { ad_revenue_opt_in: optIn };
  }
}

module.exports = SovereignEntropyNodeController;