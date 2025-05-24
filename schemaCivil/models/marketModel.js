const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const marketSchema = require('../schema/market.schema.json');
const validate = ajv.compile(marketSchema);
const { v4: uuidv4 } = require('uuid');

class MarketModel {
  constructor(chainAdapter, exchangeController) {
    this.chainAdapter = chainAdapter;
    this.exchangeController = exchangeController;
    this.markets = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a market
  async createMarket(data) {
    this.validateData(data);
    const marketId = data.id || uuidv4();
    const market = { ...data, id: marketId, type: 'market', createdAt: new Date().toISOString() };

    // Verify soulbound IDs for offers
    for (const offer of market.market.offers) {
      const isValidSoulbound = await this.chainAdapter.verifySoulboundId(offer.agent, offer.soulboundId);
      if (!isValidSoulbound) {
        throw new Error(`Invalid soulbound ID for agent ${offer.agent}`);
      }
    }

    this.markets.set(marketId, market);
    await this.chainAdapter.registerMarket(marketId, market);
    this.exchangeController.logComplianceEvent('market_created', 'system', JSON.stringify({ id: marketId, title: market.title }));
    return market;
  }

  // Get a market by ID
  getMarket(marketId) {
    const market = this.markets.get(marketId);
    if (!market) {
      throw new Error('Market not found');
    }
    return market;
  }

  // Add an offer to a market
  async addOffer(marketId, offerData) {
    const market = this.markets.get(marketId);
    if (!market) {
      throw new Error('Market not found');
    }
    if (!market.market.allowUserListings) {
      throw new Error('User listings not allowed');
    }

    this.validateData({ market: { offers: [offerData] } });
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(offerData.agent, offerData.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for agent ${offerData.agent}`);
    }

    const offerId = offerData.id || uuidv4();
    const offer = { ...offerData, id: offerId, createdAt: new Date().toISOString() };
    market.market.offers.push(offer);
    await this.chainAdapter.registerOffer(marketId, offer);
    this.exchangeController.logComplianceEvent('offer_created', offer.agent, JSON.stringify({ marketId, offerId, title: offer.title }));
    return offer;
  }

  // Verify an offer
  async verifyOffer(marketId, offerId) {
    const market = this.markets.get(marketId);
    if (!market) {
      throw new Error('Market not found');
    }

    const offer = market.market.offers.find(o => o.id === offerId);
    if (!offer) {
      throw new Error('Offer not found');
    }

    offer.verified = true;
    await this.chainAdapter.updateOffer(marketId, offer);
    this.exchangeController.logComplianceEvent('offer_verified', 'system', JSON.stringify({ marketId, offerId }));
    return offer;
  }
}

module.exports = MarketModel;