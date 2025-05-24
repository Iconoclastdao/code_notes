const express = require('express');
const { body, validationResult } = require('express-validator');
const Ajv = require('ajv');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const glob = require('glob');
const logger = require('../config/logger');
const errorHandler = require('../middleware/errorHandler');
const router = express.Router();
const ajv = new Ajv({ allErrors: true, verbose: true });

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return next(Object.assign(new Error('Missing JWT token'), { status: 401 }));
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
    next();
  } catch (error) {
    next(Object.assign(error, { status: 403 }));
  }
};

const schemaDir = path.join(__dirname, '../schema');
const schemas = {};
glob.sync(`${schemaDir}/**/*.schema.json`).forEach(file => {
  try {
    const schema = JSON.parse(fs.readFileSync(file, 'utf-8'));
    schemas[path.basename(file, '.schema.json')] = schema;
  } catch (error) {
    logger.error(`Schema load error: ${file}`, { error: error.message });
  }
});

const getSchemaValidator = (name) => schemas[name] ? ajv.compile(schemas[name]) : () => true;
const validateWith = (schemaName) => {
  const validate = getSchemaValidator(schemaName);
  return (req, res, next) => {
    if (!validate(req.body)) return res.status(400).json({ errors: validate.errors });
    next();
  };
};

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  next();
};

// 🔐 Identity
router.post('/identity/register',
  body('username').isString().notEmpty(),
  body('publicKey').isString().notEmpty(),
  validateRequest,
  validateWith('agent'),
  async (req, res, next) => {
    try {
      const result = await require('../controllers/agentController').register(req.body);
      res.json({ message: 'User registered', data: result });
    } catch (e) { next(e); }
  }
);

router.post('/identity/authenticate',
  authenticateJWT,
  body('username').isString().notEmpty(),
  body('signature').isString().notEmpty(),
  validateRequest,
  async (req, res, next) => {
    try {
      const result = await require('../controllers/agentController').authenticate(req.body);
      res.json({ message: 'User authenticated', data: result });
    } catch (e) { next(e); }
  }
);

// 🔮 Oracle
router.post('/oracle/submitData',
  authenticateJWT,
  body('data').isString().notEmpty(),
  body('signature').isString().notEmpty(),
  validateRequest,
  validateWith('sovereign-api'),
  async (req, res, next) => {
    try {
      const result = await require('../controllers/apiController').submitData(req.body);
      res.json({ message: 'Data submitted', data: result });
    } catch (e) { next(e); }
  }
);

// 🏛️ Market
router.post('/market/create',
  authenticateJWT,
  body('marketName').isString().notEmpty(),
  body('creator').isString().notEmpty(),
  validateRequest,
  validateWith('market'),
  async (req, res, next) => {
    try {
      const result = await require('../controllers/marketController').create(req.body);
      res.json({ message: 'Market created', data: result });
    } catch (e) { next(e); }
  }
);

// 🎲 Casino
router.post('/casino/play',
  authenticateJWT,
  body('gameId').isString().notEmpty(),
  body('wager').isNumeric(),
  validateRequest,
  validateWith('casino'),
  async (req, res, next) => {
    try {
      const result = await require('../controllers/casinoController').play(req.body);
      res.json({ message: 'Game played', data: result });
    } catch (e) { next(e); }
  }
);

// 📡 Feed
router.post('/feed/publish',
  authenticateJWT,
  body('channel').isString().notEmpty(),
  body('payload').isObject(),
  validateRequest,
  validateWith('feed'),
  async (req, res, next) => {
    try {
      const result = await require('../controllers/feedController').publish(req.body);
      res.json({ message: 'Feed published', data: result });
    } catch (e) { next(e); }
  }
);

// 🔥 Ritual
router.post('/ritual/execute',
  authenticateJWT,
  body('ritualId').isString().notEmpty(),
  body('inputs').isObject(),
  validateRequest,
  validateWith('ritual'),
  async (req, res, next) => {
    try {
      const result = await require('../controllers/ritualController').execute(req.body);
      res.json({ message: 'Ritual executed', data: result });
    } catch (e) { next(e); }
  }
);

// 🗳️ Governance
router.post('/governance/propose',
  authenticateJWT,
  body('proposal').isObject().notEmpty(),
  validateRequest,
  validateWith('governance'),
  async (req, res, next) => {
    try {
      const result = await require('../controllers/governanceController').propose(req.body);
      res.json({ message: 'Proposal submitted', data: result });
    } catch (e) { next(e); }
  }
);

// Error middleware
router.use(errorHandler);

module.exports = router;