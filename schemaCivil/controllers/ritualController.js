const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const ritualSchema = require('../schema/ritual.schema.json');
const validate = ajv.compile(ritualSchema);

class RitualController {
  constructor(exchangeController) {
    this.exchangeController = exchangeController;
    this.ritualData = {
      rituals: [],
      signals: [],
      consensusRecords: []
    };
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    return valid;
  }

  initiateSignal(initiator, signalType, payload) {
    const signal = {
      id: crypto.randomUUID(),
      initiator,
      type: signalType,
      payload,
      timestamp: new Date().toISOString(),
      status: 'pending',
      verificationCount: 0
    };
    this.ritualData.signals.push(signal);
    this.validateData(this.ritualData);
    this.exchangeController.logComplianceEvent('signal_initiated', initiator, JSON.stringify({ signalType, payload }));
    return signal;
  }

  verifySignal(signalId, verifier, isValid) {
    const signal = this.ritualData.signals.find(s => s.id === signalId);
    if (!signal) throw new Error('Signal not found');
    signal.verificationCount += 1;
    signal.status = isValid ? 'verified' : 'rejected';
    this.validateData(this.ritualData);
    this.exchangeController.logComplianceEvent('signal_verified', verifier, JSON.stringify({ signalId, isValid }));
    return signal;
  }

  executeRitual(ritualId, initiator, actions) {
    const ritual = {
      id: ritualId || crypto.randomUUID(),
      initiator,
      actions: actions.map(a => ({ type: a.type, target: a.target, executedAt: new Date().toISOString() })),
      status: 'completed',
      timestamp: new Date().toISOString()
    };
    this.ritualData.rituals.push(ritual);
    this.validateData(this.ritualData);
    this.exchangeController.logComplianceEvent('ritual_executed', initiator, JSON.stringify({ ritualId, actions }));
    return ritual;
  }

  quorumConsensusCheck(signalId, requiredVerifications) {
    const signal = this.ritualData.signals.find(s => s.id === signalId);
    if (!signal) throw new Error('Signal not found');
    const consensus = {
      signalId,
      reached: signal.verificationCount >= requiredVerifications,
      timestamp: new Date().toISOString(),
      verifications: signal.verificationCount
    };
    this.ritualData.consensusRecords.push(consensus);
    this.validateData(this.ritualData);
    if (consensus.reached) {
      this.executeRitual(crypto.randomUUID(), signal.initiator, [{ type: 'consensus_approved', target: signalId }]);
    }
    return consensus;
  }

  getRitualData() {
    return this.ritualData;
  }
}

module.exports = RitualController;