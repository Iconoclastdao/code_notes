const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const apiSchema = require('../schema/api/sovereign-api.schema.json');
const validate = ajv.compile(apiSchema);

class ApiController {
  constructor(exchangeController) {
    this.exchangeController = exchangeController;
    this.apiData = {
      endpoints: [],
      requests: [],
      responses: []
    };
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    return valid;
  }

  async registerEndpoint(req, res) {
    try {
      const { path, method, description } = req.body;
      const endpoint = {
        id: crypto.randomUUID(),
        path,
        method: method.toUpperCase(),
        description,
        status: 'active',
        createdAt: new Date().toISOString()
      };
      this.apiData.endpoints.push(endpoint);
      this.validateData(this.apiData);
      this.exchangeController.logComplianceEvent('endpoint_registered', 'system', JSON.stringify({ path, method }));
      res.status(201).json(endpoint);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async logRequest(req, res) {
    try {
      const { endpointId, userId, payload } = req.body;
      const endpoint = this.apiData.endpoints.find(e => e.id === endpointId);
      if (!endpoint) throw new Error('Endpoint not found');
      const request = {
        id: crypto.randomUUID(),
        endpoint: endpointId,
        user: userId || 'anonymous',
        payload,
        timestamp: new Date().toISOString(),
        status: 'received'
      };
      this.apiData.requests.push(request);
      this.validateData(this.apiData);
      this.exchangeController.logComplianceEvent('api_request', request.user, JSON.stringify({ endpointId, payload }));
      res.status(201).json(request);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async logResponse(req, res) {
    try {
      const { requestId, data, statusCode } = req.body;
      const request = this.apiData.requests.find(r => r.id === requestId);
      if (!request) throw new Error('Request not found');
      const response = {
        id: crypto.randomUUID(),
        request: requestId,
        data,
        statusCode,
        timestamp: new Date().toISOString()
      };
      this.apiData.responses.push(response);
      this.validateData(this.apiData);
      this.exchangeController.logComplianceEvent('api_response', request.user, JSON.stringify({ requestId, statusCode }));
      res.status(201).json(response);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async getEndpointRequests(req, res) {
    try {
      const endpointId = req.params.id;
      const requests = this.apiData.requests.filter(r => r.endpoint === endpointId);
      res.status(200).json(requests);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  async getRequestResponses(req, res) {
    try {
      const requestId = req.params.id;
      const responses = this.apiData.responses.filter(r => r.request === requestId);
      res.status(200).json(responses);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  getApiData() {
    return this.apiData;
  }
}

module.exports = ApiController;