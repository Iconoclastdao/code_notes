const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const casinoSchema = require('../schema/casino/casino.schema.json');

class CasinoController {
  constructor(exchangeController, financialController) {
    this.exchangeController = exchangeController;
    this.financialController = financialController;
    this.validate = ajv.compile(casinoSchema);
    this.casinoData = {
      id: 'sovereign-casino',
      title: 'Sovereign Casino',
      type: 'casino',
      version: '1.0.0',
      layout: { x: 0, y: 0, w: 12, h: 6, responsive: true, theme: 'light' },
      casino: {
        entropy: { entropySource: 'onchain', contractAddress: '0x0000000000000000000000000000000000000000', method: 'getEntropy', cooldown: 15 },
        games: [],
        sessions: [],
        rewardPools: [],
        agentWagers: true,
        transactionHooks: {},
        auditTrail: true,
        leaderboard: { enabled: true, entries: [] },
        compliance: { kycRequired: false, restrictedJurisdictions: [], auditLog: [] }
      }
    };
  }

  validateData(data) {
    const valid = this.validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(this.validate.errors, null, 2)}`);
    return valid;
  }

  async createGame(req, res) {
    try {
      const { name, engine, rules, minBet = 1, maxBet = 1000, currency = 'SOL', payoutTable, requiresEntropy = true } = req.body;
      const game = {
        id: crypto.randomUUID(),
        name,
        engine,
        rules,
        minBet,
        maxBet,
        currency,
        payoutTable,
        requiresEntropy,
        status: 'active',
        totalBets: 0,
        createdAt: new Date().toISOString()
      };
      this.casinoData.casino.games.push(game);
      this.validateData(this.casinoData);
      this.exchangeController.logComplianceEvent('game_created', 'system', JSON.stringify({ name, engine }));
      res.status(201).json(game);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async startSession(req, res) {
    try {
      const { userId, gameId } = req.body;
      const game = this.casinoData.casino.games.find(g => g.id === gameId && g.status === 'active');
      if (!game) throw new Error('Active game not found');
      const session = {
        id: crypto.randomUUID(),
        user: userId,
        game: gameId,
        startTime: new Date().toISOString(),
        betsPlaced: 0,
        totalWagered: 0,
        totalWon: 0,
        status: 'active'
      };
      this.casinoData.casino.sessions.push(session);
      this.validateData(this.casinoData);
      this.exchangeController.logComplianceEvent('session_started', userId, JSON.stringify({ gameId }));
      res.status(201).json(session);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async placeBet(req, res) {
    try {
      const { userId, gameId, amount, sessionId } = req.body;
      const game = this.casinoData.casino.games.find(g => g.id === gameId && g.status === 'active');
      const session = this.casinoData.casino.sessions.find(s => s.id === sessionId && s.user === userId && s.status === 'active');
      if (!game || !session) throw new Error('Active game or session not found');
      if (amount < game.minBet || amount > game.maxBet) throw new Error('Bet amount out of range');
      if (this.casinoData.casino.compliance.kycRequired && !this.exchangeController.getExchangeData().exchange.users.find(u => u.id === userId && u.kycLevel !== 'none')) {
        throw new Error('KYC required');
      }
      const bet = {
        id: crypto.randomUUID(),
        user: userId,
        game: gameId,
        amount,
        status: 'placed',
        timestamp: new Date().toISOString()
      };
      game.totalBets += amount;
      session.betsPlaced += 1;
      session.totalWagered += amount;
      this.financialController.logTransaction(userId, 'bet_placed', { gameId, amount });
      this.casinoData.casino.compliance.auditLog.push({ event: 'bet_placed', user: userId, timestamp: new Date().toISOString(), details: JSON.stringify({ gameId, amount }) });
      this.validateData(this.casinoData);
      this.exchangeController.logComplianceEvent('bet_placed', userId, JSON.stringify({ gameId, amount }));
      res.status(201).json(bet);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async settleBet(req, res) {
    try {
      const { betId, outcome, rewardAmount, sessionId } = req.body;
      const bet = this.casinoData.casino.bets.find(b => b.id === betId && b.status === 'placed');
      const session = this.casinoData.casino.sessions.find(s => s.id === sessionId && s.status === 'active');
      if (!bet || !session) throw new Error('Invalid bet or session');
      bet.status = outcome === 'win' ? 'won' : outcome === 'lose' ? 'lost' : 'draw';
      bet.settledAt = new Date().toISOString();
      let reward = null;
      if (outcome === 'win' && rewardAmount > 0) {
        reward = {
          id: crypto.randomUUID(),
          bet: betId,
          user: bet.user,
          amount: rewardAmount,
          timestamp: new Date().toISOString()
        };
        this.casinoData.casino.rewards.push(reward);
        session.totalWon += rewardAmount;
        this.financialController.logTransaction(bet.user, 'reward_distributed', { betId, rewardAmount });
        this.updateLeaderboard(bet.user, rewardAmount);
      }
      if (outcome !== 'win' && this.casinoData.casino.transactionHooks.onLose) {
        // Trigger onLose hook (assumed to be external call)
      }
      this.casinoData.casino.compliance.auditLog.push({ event: 'bet_settled', user: bet.user, timestamp: new Date().toISOString(), details: JSON.stringify({ betId, outcome, rewardAmount }) });
      this.validateData(this.casinoData);
      this.exchangeController.logComplianceEvent('bet_settled', bet.user, JSON.stringify({ betId, outcome, rewardAmount }));
      res.status(200).json({ bet, reward });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async fetchEntropy(req, res) {
    try {
      const { agentId } = req.body;
      const entropy = this.casinoData.casino.entropy;
      if (entropy.agentTrigger && agentId !== entropy.agentTrigger) throw new Error('Unauthorized agent');
      const now = new Date();
      if (entropy.lastFetched && (now - new Date(entropy.lastFetched)) / 1000 < entropy.cooldown) {
        throw new Error('Entropy fetch on cooldown');
      }
      // Simulate entropy fetch from Entropy.sol
      const entropyValue = crypto.randomUUID(); // Replace with actual contract call
      entropy.entropyValue = entropyValue;
      entropy.lastFetched = now.toISOString();
      this.validateData(this.casinoData);
      this.exchangeController.logComplianceEvent('entropy_fetched', agentId || 'system', JSON.stringify({ entropyValue }));
      res.status(200).json({ entropyValue, timestamp: entropy.lastFetched });
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async updateLeaderboard(userId, scoreIncrement) {
    const leaderboard = this.casinoData.casino.leaderboard;
    if (!leaderboard.enabled) return;
    let entry = leaderboard.entries.find(e => e.user === userId);
    if (!entry) {
      entry = { user: userId, score: 0, lastUpdated: new Date().toISOString() };
      leaderboard.entries.push(entry);
    }
    entry.score += scoreIncrement;
    entry.lastUpdated = new Date().toISOString();
    this.validateData(this.casinoData);
  }

  async getUserSessions(req, res) {
    try {
      const userId = req.params.userId;
      const sessions = this.casinoData.casino.sessions.filter(s => s.user === userId);
      res.status(200).json(sessions);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  getCasinoData() {
    return this.casinoData;
  }
}

module.exports = CasinoController;