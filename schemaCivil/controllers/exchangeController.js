const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const schema = require('./exchange.schema.json'); // Assume schema is imported
const validate = ajv.compile(schema);

class ExchangeController {
  constructor() {
    this.exchangeData = {
      id: 'sovereign-exchange',
      title: 'Sovereign Exchange',
      type: 'exchange',
      version: '1.0.0',
      layout: { x: 0, y: 0, w: 12, h: 6, responsive: true, theme: 'light' },
      exchange: {
        pairs: [],
        orders: [],
        positions: [],
        liquidations: [],
        pools: [],
        loans: [],
        safety: { minCollateralRatio: 1.5, autoLiquidate: true, aiGuardianEnabled: false },
        users: [],
        compliance: { kycRequired: false, amlChecks: false, restrictedJurisdictions: [], auditLog: [] }
      }
    };
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    return valid;
  }

  addTradingPair(base, quote, oracleFeed, feeRate = 0.001, maxLeverage = 10) {
    const pair = {
      base,
      quote,
      oracleFeed,
      feeRate,
      maxLeverage,
      minTradeSize: 0.01,
      tickSize: 0.01,
      status: 'active',
      circuitBreaker: { enabled: false, priceChangeThreshold: 0.1, haltDuration: 300 }
    };
    this.exchangeData.exchange.pairs.push(pair);
    this.validateData(this.exchangeData);
    return pair;
  }

  placeOrder(userId, pair, side, type, size, price, leverage = 1, options = {}) {
    const order = {
      id: crypto.randomUUID(),
      user: userId,
      pair,
      side,
      type,
      size,
      price,
      leverage,
      timestamp: new Date().toISOString(),
      status: 'open',
      trailingDistance: options.trailingDistance || 0,
      stopPrice: options.stopPrice || 0,
      timeInForce: options.timeInForce || 'GTC',
      postOnly: options.postOnly || false
    };
    this.exchangeData.exchange.orders.push(order);
    this.validateData(this.exchangeData);
    return order;
  }

  openPosition(userId, pair, size, entryPrice, leverage, margin) {
    const position = {
      user: userId,
      pair,
      size,
      entryPrice,
      leverage,
      margin,
      liquidationPrice: this.calculateLiquidationPrice(entryPrice, leverage, size),
      unrealizedPnL: 0,
      fundingRate: 0.0001,
      openTimestamp: new Date().toISOString(),
      lastUpdated: new Date().toISOString()
    };
    this.exchangeData.exchange.positions.push(position);
    this.validateData(this.exchangeData);
    return position;
  }

  calculateLiquidationPrice(entryPrice, leverage, size) {
    return size > 0 ? entryPrice * (1 - 1 / leverage) : entryPrice * (1 + 1 / leverage);
  }

  liquidatePosition(userId, pair, price, reason) {
    const position = this.exchangeData.exchange.positions.find(
      p => p.user === userId && p.pair === pair
    );
    if (!position) throw new Error('Position not found');
    const liquidation = {
      user: userId,
      pair,
      liquidatedAt: price,
      timestamp: new Date().toISOString(),
      reason,
      lossAmount: Math.abs(position.size * (price - position.entryPrice)),
      liquidator: 'system'
    };
    position.unrealizedPnL = liquidation.lossAmount * -1;
    position.lastUpdated = new Date().toISOString();
    this.exchangeData.exchange.liquidations.push(liquidation);
    this.exchangeData.exchange.positions = this.exchangeData.exchange.positions.filter(
      p => p !== position
    );
    this.validateData(this.exchangeData);
    return liquidation;
  }

  addLiquidity(token, userId, amount) {
    const pool = this.exchangeData.exchange.pools.find(p => p.token === token);
    const share = pool ? amount / (pool.totalLiquidity + amount) : 1;
    const provider = { user: userId, amount, share, joinTimestamp: new Date().toISOString() };
    
    if (!pool) {
      this.exchangeData.exchange.pools.push({
        token,
        totalLiquidity: amount,
        providers: [provider],
        rewardsRate: 0.01,
        status: 'active',
        lockupPeriod: 0,
        swapFee: 0.003
      });
    } else {
      pool.totalLiquidity += amount;
      pool.providers.push(provider);
    }
    this.validateData(this.exchangeData);
    return provider;
  }

  createLoan(borrower, collateral, amount, rate, dueDate) {
    const loan = {
      borrower,
      collateral,
      amount,
      rate,
      dueDate,
      status: 'active',
      collateralRatio: 1.5,
      interestAccrued: 0
    };
    this.exchangeData.exchange.loans.push(loan);
    this.validateData(this.exchangeData);
    return loan;
  }

  registerUser(walletAddress, kycLevel = 'none') {
    const user = {
      id: crypto.randomUUID(),
      walletAddress,
      status: 'active',
      kycLevel,
      lastLogin: new Date().toISOString(),
      riskScore: 0
    };
    this.exchangeData.exchange.users.push(user);
    this.validateData(this.exchangeData);
    return user;
  }

  logComplianceEvent(event, userId, details) {
    const log = {
      event,
      timestamp: new Date().toISOString(),
      user: userId,
      details
    };
    this.exchangeData.exchange.compliance.auditLog.push(log);
    this.validateData(this.exchangeData);
    return log;
  }

  checkSafety(userId, pair, price) {
    const position = this.exchangeData.exchange.positions.find(
      p => p.user === userId && p.pair === pair
    );
    if (!position) return true;
    const { minCollateralRatio, autoLiquidate } = this.exchangeData.exchange.safety;
    const collateralValue = position.margin * price;
    const requiredCollateral = position.size * position.leverage * minCollateralRatio;
    if (collateralValue < requiredCollateral && autoLiquidate) {
      this.liquidatePosition(userId, pair, price, 'margin-call');
      return false;
    }
    return true;
  }

  getExchangeData() {
    return this.exchangeData;
  }
}

module.exports = ExchangeController;