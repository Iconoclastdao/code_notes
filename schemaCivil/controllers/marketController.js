const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const marketSchema = require('../schema/market.schema.json');
const validate = ajv.compile(marketSchema);
const { v4: uuidv4 } = require('uuid');

class MarketController {
  constructor(exchangeController, chainAdapter) {
    this.exchangeController = exchangeController;
    this.chainAdapter = chainAdapter;
    this.markets = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a new market
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
    return { id: marketId };
  }

  // Get a market by ID
  getMarket(marketId) {
    const market = this.markets.get(marketId);
    if (!market) {
      throw new Error('Market not found');
    }
    return market;
  }

  // Create a new offer in a market
  async createOffer(marketId, offerData) {
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

    // Distribute karma wage for listing
    await this.chainAdapter.distributeKarmaWage(offer.agent, market.market.karmaWage);
    await this.chainAdapter.registerOffer(marketId, offer);
    this.exchangeController.logComplianceEvent('offer_created', offer.agent, JSON.stringify({ marketId, offerId, title: offer.title }));
    return { id: offerId };
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

    // Trigger onVerify hook
    if (market.market.transactionHooks?.onVerify) {
      await this.chainAdapter.executeHook(market.market.transactionHooks.onVerify, { marketId, offerId });
    }

    offer.verified = true;
    await this.chainAdapter.updateOffer(marketId, offer);
    this.exchangeController.logComplianceEvent('offer_verified', 'system', JSON.stringify({ marketId, offerId }));
    return { message: 'Offer verified' };
  }

  // Purchase an offer
  async purchaseOffer(marketId, offerId, buyerId, buyerSoulboundId) {
    const market = this.markets.get(marketId);
    if (!market) {
      throw new Error('Market not found');
    }

    const offer = market.market.offers.find(o => o.id === offerId);
    if (!offer || !offer.verified) {
      throw new Error('Offer not found or not verified');
    }

    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(buyerId, buyerSoulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for buyer ${buyerId}`);
    }

    // Process payment and fees
    await this.chainAdapter.processPayment(buyerId, offer.agent, offer.price, offer.currency, market.market.feeStructure);

    // Trigger onBuy hook
    if (market.market.transactionHooks?.onBuy) {
      await this.chainAdapter.executeHook(market.market.transactionHooks.onBuy, { marketId, offerId, buyerId });
    }

    // Update reputation and karma
    await this.chainAdapter.updateReputation(offer.agent, 1); // Example: +1 for successful sale
    await this.chainAdapter.distributeKarmaWage(buyerId, market.market.karmaWage);
    this.exchangeController.logComplianceEvent('offer_purchased', buyerId, JSON.stringify({ marketId, offerId, buyerId }));

    return { message: 'Purchase successful', accessPayload: offer.accessPayload };
  }

  // Check for expired offers and trigger hooks
  async checkExpiredOffers(marketId) {
    const market = this.markets.get(marketId);
    if (!market) {
      throw new Error('Market not found');
    }

    const now = new Date();
    for (const offer of market.market.offers) {
      if (offer.expiry && new Date(offer.expiry) < now) {
        if (market.market.transactionHooks?.onExpire) {
          await this.chainAdapter.executeHook(market.market.transactionHooks.onExpire, { marketId, offerId: offer.id });
        }
        this.exchangeController.logComplianceEvent('offer_expired', 'system', JSON.stringify({ marketId, offerId: offer.id }));
      }
    }
  }
}

module.exports = MarketController;