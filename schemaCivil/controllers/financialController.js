const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const financialSchema = require('../schema/financial/financial.schema.json');
const validate = ajv.compile(financialSchema);

class FinancialController {
  constructor(exchangeController) {
    this.exchangeController = exchangeController;
    this.financialData = {
      portfolios: [],
      transactions: [],
      reports: [],
      collateralPools: []
    };
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    return valid;
  }

  createPortfolio(userId, assets) {
    const portfolio = {
      id: crypto.randomUUID(),
      user: userId,
      assets: assets.map(a => ({ token: a.token, amount: a.amount, value: 0 })),
      createdAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
      totalValue: 0
    };
    this.financialData.portfolios.push(portfolio);
    this.validateData(this.financialData);
    this.logTransaction(userId, 'portfolio_create', { portfolioId: portfolio.id });
    return portfolio;
  }

  logTransaction(userId, type, details) {
    const transaction = {
      id: crypto.randomUUID(),
      user: userId,
      type,
      details,
      timestamp: new Date().toISOString(),
      status: 'completed'
    };
    this.financialData.transactions.push(transaction);
    this.validateData(this.financialData);
    this.exchangeController.logComplianceEvent('financial_transaction', userId, JSON.stringify(details));
    return transaction;
  }

  generateReport(userId, startDate, endDate) {
    const transactions = this.financialData.transactions.filter(
      t => t.user === userId && t.timestamp >= startDate && t.timestamp <= endDate
    );
    const portfolio = this.financialData.portfolios.find(p => p.user === userId);
    const report = {
      id: crypto.randomUUID(),
      user: userId,
      period: { start: startDate, end: endDate },
      transactions,
      portfolioSnapshot: portfolio ? { ...portfolio, lastUpdated: new Date().toISOString() } : null,
      generatedAt: new Date().toISOString()
    };
    this.financialData.reports.push(report);
    this.validateData(this.financialData);
    return report;
  }

  manageCollateralPool(userId, token, amount, action) {
    let pool = this.financialData.collateralPools.find(p => p.token === token);
    if (action === 'add') {
      if (!pool) {
        pool = { token, totalCollateral: 0, providers: [] };
        this.financialData.collateralPools.push(pool);
      }
      const provider = pool.providers.find(p => p.user === userId) || { user: userId, amount: 0 };
      provider.amount += amount;
      pool.totalCollateral += amount;
      if (!pool.providers.includes(provider)) pool.providers.push(provider);
      this.logTransaction(userId, 'collateral_add', { token, amount });
    } else if (action === 'withdraw' && pool) {
      const provider = pool.providers.find(p => p.user === userId);
      if (!provider || provider.amount < amount) throw new Error('Insufficient collateral');
      provider.amount -= amount;
      pool.totalCollateral -= amount;
      this.logTransaction(userId, 'collateral_withdraw', { token, amount });
    } else {
      throw new Error('Invalid action or pool not found');
    }
    this.validateData(this.financialData);
    return pool;
  }

  integrateWithExchange(userId, loanId, collateralAmount) {
    const loan = this.exchangeController.getExchangeData().exchange.loans.find(l => l.id === loanId);
    if (!loan || loan.borrower !== userId) throw new Error('Invalid loan');
    this.manageCollateralPool(userId, loan.collateral, collateralAmount, 'add');
    loan.collateralRatio = (loan.amount + collateralAmount) / loan.amount;
    this.validateData(this.financialData);
    return loan;
  }

  getFinancialData() {
    return this.financialData;
  }
}

module.exports = FinancialController;