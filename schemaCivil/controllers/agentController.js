const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const Agent = require('../models/agentModel');
const agentSchema = require('../schema/agent/agent.schema.json');
const validate = ajv.compile(agentSchema);

class AgentController {
  constructor(exchangeController) {
    this.exchangeController = exchangeController;
    this.agentData = {
      agents: [],
      tasks: [],
      entropyRecords: []
    };
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    return valid;
  }

  async createAgent(req, res) {
    try {
      const { type, config } = req.body;
      const agent = {
        id: crypto.randomUUID(),
        type,
        config,
        status: 'active',
        createdAt: new Date().toISOString(),
        lastActive: new Date().toISOString()
      };
      this.agentData.agents.push(agent);
      this.validateData(this.agentData);
      const newAgent = await Agent.create(agent);
      this.exchangeController.logComplianceEvent('agent_created', agent.id, JSON.stringify({ type }));
      res.status(201).json(newAgent);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async getAllAgents(req, res) {
    try {
      const agents = await Agent.find();
      res.status(200).json(agents);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  async getAgentById(req, res) {
    try {
      const agent = await Agent.findById(req.params.id);
      if (!agent) {
        return res.status(404).json({ message: 'Agent not found' });
      }
      res.status(200).json(agent);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  async updateAgent(req, res) {
    try {
      const { status, config } = req.body;
      const agent = this.agentData.agents.find(a => a.id === req.params.id);
      if (!agent) {
        return res.status(404).json({ message: 'Agent not found' });
      }
      if (status) agent.status = status;
      if (config) agent.config = config;
      agent.lastActive = new Date().toISOString();
      this.validateData(this.agentData);
      const updatedAgent = await Agent.findByIdAndUpdate(req.params.id, { status, config, lastActive: agent.lastActive }, { new: true });
      if (!updatedAgent) {
        return res.status(404).json({ message: 'Agent not found' });
      }
      this.exchangeController.logComplianceEvent('agent_updated', req.params.id, JSON.stringify({ status, config }));
      res.status(200).json(updatedAgent);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async deleteAgent(req, res) {
    try {
      const deletedAgent = await Agent.findByIdAndDelete(req.params.id);
      if (!deletedAgent) {
        return res.status(404).json({ message: 'Agent not found' });
      }
      this.agentData.agents = this.agentData.agents.filter(a => a.id !== req.params.id);
      this.validateData(this.agentData);
      this.exchangeController.logComplianceEvent('agent_deleted', req.params.id, JSON.stringify({}));
      res.status(200).json({ message: 'Agent deleted successfully' });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  async assignTask(req, res) {
    try {
      const { agentId, taskType, target, params } = req.body;
      const agent = this.agentData.agents.find(a => a.id === agentId);
      if (!agent) throw new Error('Agent not found');
      const task = {
        id: crypto.randomUUID(),
        agent: agentId,
        type: taskType,
        target,
        params,
        status: 'pending',
        createdAt: new Date().toISOString()
      };
      this.agentData.tasks.push(task);
      this.validateData(this.agentData);
      await Agent.findByIdAndUpdate(agentId, { $push: { tasks: task } });
      this.exchangeController.logComplianceEvent('task_assigned', agentId, JSON.stringify({ taskType, target }));
      res.status(201).json(task);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async recordEntropy(req, res) {
    try {
      const { agentId, entropyValue } = req.body;
      const entropy = {
        id: crypto.randomUUID(),
        agent: agentId,
        value: entropyValue,
        timestamp: new Date().toISOString()
      };
      this.agentData.entropyRecords.push(entropy);
      this.validateData(this.agentData);
      await Agent.findByIdAndUpdate(agentId, { $push: { entropyRecords: entropy } });
      this.exchangeController.logComplianceEvent('entropy_recorded', agentId, JSON.stringify({ entropyValue }));
      res.status(201).json(entropy);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async getAgentTasks(req, res) {
    try {
      const agent = await Agent.findById(req.params.id);
      if (!agent) {
        return res.status(404).json({ message: 'Agent not found' });
      }
      res.status(200).json(agent.tasks || []);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  getAgentData() {
    return this.agentData;
  }
}

module.exports = AgentController;