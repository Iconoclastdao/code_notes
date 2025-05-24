const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const nodeSchema = require('../schema/nodes/sovereignEntropyNode.schema.json');
const validate = ajv.compile(nodeSchema);
const { v4: uuidv4 } = require('uuid');

class SovereignEntropyNodeModel {
  constructor(chainAdapter, exchangeController) {
    this.chainAdapter = chainAdapter;
    this.exchangeController = exchangeController;
    this.nodes = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a node
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
    return node;
  }

  // Get a node by ID
  getNode(nodeId) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }
    return node;
  }

  // Fetch entropy
  async fetchEntropy(nodeId, contractIndex = 0) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error('Node not found');
    }

    const { contracts, method, format, cacheTTL, retryPolicy, postProcess } = node.entropy_agent;
    let entropy;
    let attempts = 0;

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

    let processedEntropy = entropy;
    if (postProcess?.type !== 'none') {
      processedEntropy = await this.chainAdapter.executePostProcess(postProcess.type, postProcess.callback, entropy);
    }

    await this.chainAdapter.cacheEntropy(nodeId, processedEntropy, cacheTTL);
    this.exchangeController.logComplianceEvent('entropy_fetched', node.wallet_address, JSON.stringify({ node_id: nodeId, contract: contracts[contractIndex] }));
    return { entropy: processedEntropy };
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
    await this.chainAdapter.updateNode(nodeId, node);
    this.exchangeController.logComplianceEvent('project_created', node.wallet_address, JSON.stringify({ node_id: nodeId, projectId }));
    return { id: projectId };
  }
}

module.exports = SovereignEntropyNodeModel;