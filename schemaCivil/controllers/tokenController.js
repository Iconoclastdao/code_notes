const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const tokenSchema = require('../schema/token.schema.json');

class TokenController {
  constructor(exchangeController, financialController) {
    this.exchangeController = exchangeController;
    this.financialController = financialController;
    this.validate = ajv.compile(tokenSchema);
    this.tokenData = {
      id: 'sovereign-token',
      title: 'Sovereign Token',
      type: 'token',
      version: '1.0.0',
      token: {
        metadata: {
          name: 'Sovereign Token',
          symbol: 'SVR',
          decimals: 18,
          totalSupply: 0,
          contractAddress: '0x0000000000000000000000000000000000000000',
          standard: 'ERC20',
          createdAt: new Date().toISOString()
        },
        balances: [],
        transfers: [],
        staking: { pools: [], enabled: true },
        governance: { proposals: [], minVotingPower: 100, votingPeriod: 604800 },
        compliance: { kycRequired: false, restrictedJurisdictions: [], auditLog: [] }
      }
    };
  }

  validateData(data) {
    const valid = this.validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(this.validate.errors, null, 2)}`);
    return valid;
  }

  async createToken(req, res) {
    try {
      const { name, symbol, decimals, totalSupply, contractAddress, standard } = req.body;
      this.tokenData.token.metadata = {
        name,
        symbol,
        decimals,
        totalSupply,
        contractAddress,
        standard,
        createdAt: new Date().toISOString()
      };
      this.validateData(this.tokenData);
      this.exchangeController.logComplianceEvent('token_created', 'system', JSON.stringify({ name, symbol }));
      res.status(201).json(this.tokenData.token.metadata);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async transferTokens(req, res) {
    try {
      const { from, to, amount } = req.body;
      if (this.tokenData.token.compliance.kycRequired && !this.exchangeController.getExchangeData().exchange.users.find(u => u.id === from && u.kycLevel !== 'none')) {
        throw new Error('KYC required');
      }
      const maxLimit = this.tokenData.token.compliance.maxTransferLimit;
      if (maxLimit && amount > maxLimit) throw new Error('Transfer exceeds limit');
      let fromBalance = this.tokenData.token.balances.find(b => b.user === from);
      if (!fromBalance) {
        fromBalance = { user: from, amount: 0, lockedAmount: 0, lastUpdated: new Date().toISOString() };
        this.tokenData.token.balances.push(fromBalance);
      }
      if (fromBalance.amount < amount) throw new Error('Insufficient balance');
      let toBalance = this.tokenData.token.balances.find(b => b.user === to);
      if (!toBalance) {
        toBalance = { user: to, amount: 0, lockedAmount: 0, lastUpdated: new Date().toISOString() };
        this.tokenData.token.balances.push(toBalance);
      }
      fromBalance.amount -= amount;
      toBalance.amount += amount;
      const transfer = {
        id: crypto.randomUUID(),
        from,
        to,
        amount,
        timestamp: new Date().toISOString(),
        status: 'completed',
        txHash: `0x${crypto.randomBytes(32).toString('hex')}`
      };
      this.tokenData.token.transfers.push(transfer);
      this.financialController.logTransaction(from, 'token_transfer', { to, amount });
      this.tokenData.token.compliance.auditLog.push({ event: 'transfer', user: from, timestamp: new Date().toISOString(), details: JSON.stringify({ to, amount }) });
      this.validateData(this.tokenData);
      this.exchangeController.logComplianceEvent('token_transferred', from, JSON.stringify({ to, amount }));
      res.status(201).json(transfer);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async stakeTokens(req, res) {
    try {
      const { userId, poolId, amount } = req.body;
      const pool = this.tokenData.token.staking.pools.find(p => p.id === poolId);
      if (!pool) throw new Error('Staking pool not found');
      let balance = this.tokenData.token.balances.find(b => b.user === userId);
      if (!balance || balance.amount < amount) throw new Error('Insufficient balance');
      balance.amount -= amount;
      balance.lockedAmount += amount;
      balance.lastUpdated = new Date().toISOString();
      let staker = pool.stakers.find(s => s.user === userId);
      if (!staker) {
        staker = { user: userId, amount: 0, stakedAt: new Date().toISOString(), rewardsEarned: 0 };
        pool.stakers.push(staker);
      }
      staker.amount += amount;
      pool.totalStaked += amount;
      this.financialController.logTransaction(userId, 'stake_tokens', { poolId, amount });
      this.tokenData.token.compliance.auditLog.push({ event: 'stake', user: userId, timestamp: new Date().toISOString(), details: JSON.stringify({ poolId, amount }) });
      this.validateData(this.tokenData);
      this.exchangeController.logComplianceEvent('tokens_staked', userId, JSON.stringify({ poolId, amount }));
      res.status(201).json(staker);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async createProposal(req, res) {
    try {
      const { creator, description, endTime } = req.body;
      const balance = this.tokenData.token.balances.find(b => b.user === creator);
      if (!balance || balance.amount < this.tokenData.token.governance.minVotingPower) {
        throw new Error('Insufficient voting power');
      }
      const proposal = {
        id: crypto.randomUUID(),
        creator,
        description,
        status: 'proposed',
        votes: [],
        createdAt: new Date().toISOString(),
        endTime
      };
      this.tokenData.token.governance.proposals.push(proposal);
      this.validateData(this.tokenData);
      this.exchangeController.logComplianceEvent('proposal_created', creator, JSON.stringify({ description }));
      res.status(201).json(proposal);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async voteOnProposal(req, res) {
    try {
      const { userId, proposalId, vote } = req.body;
      const proposal = this.tokenData.token.governance.proposals.find(p => p.id === proposalId && p.status === 'active');
      if (!proposal) throw new Error('Active proposal not found');
      const balance = this.tokenData.token.balances.find(b => b.user === userId);
      if (!balance || balance.amount < this.tokenData.token.governance.minVotingPower) {
        throw new Error('Insufficient voting power');
      }
      proposal.votes.push({ user: userId, vote, weight: balance.amount });
      this.tokenData.token.compliance.auditLog.push({ event: 'vote', user: userId, timestamp: new Date().toISOString(), details: JSON.stringify({ proposalId, vote }) });
      this.validateData(this.tokenData);
      this.exchangeController.logComplianceEvent('proposal_voted', userId, JSON.stringify({ proposalId, vote }));
      res.status(200).json(proposal);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async getUserBalance(req, res) {
    try {
      const userId = req.params.userId;
      const balance = this.tokenData.token.balances.find(b => b.user === userId) || { user: userId, amount: 0, lockedAmount: 0 };
      res.status(200).json(balance);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  getTokenData() {
    return this.tokenData;
  }
}

module.exports = TokenController;