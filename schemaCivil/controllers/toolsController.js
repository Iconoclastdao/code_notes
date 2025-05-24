const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const toolsSchema = require('../schema/tools.schema.json');

class ToolsController {
  constructor(exchangeController) {
    this.exchangeController = exchangeController;
    this.validate = ajv.compile(toolsSchema);
    this.toolsData = {
      id: 'sovereign-tools',
      title: 'Sovereign Tools',
      type: 'tools',
      version: '1.0.0',
      layout: { x: 0, y: 0, w: 12, h: 6, responsive: true, theme: 'light' },
      tools: {
        codeEditor: {
          language: 'javascript',
          mode: 'code',
          code: '// Start your sovereign expression here',
          runButton: true,
          enableAIHinting: false,
          output: '',
          versionControl: [],
          linting: { enabled: true, rules: {} },
          debugging: { breakpoints: [], watchVariables: [] }
        },
        dataVisualizer: {
          dataSource: '',
          visualizationType: 'bar',
          config: { interactive: true },
          filters: []
        },
        contractDeployer: {
          contractCode: '',
          network: 'testnet',
          compilerVersion: 'latest',
          constructorArgs: [],
          deployments: []
        },
        apiTester: {
          endpoint: '',
          method: 'GET',
          headers: {},
          body: '',
          requests: []
        }
      },
      compliance: { auditLog: [] }
    };
  }

  validateData(data) {
    const valid = this.validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(this.validate.errors, null, 2)}`);
    return valid;
  }

  async updateCodeEditor(req, res) {
    try {
      const { userId, language, mode, code, runButton, enableAIHinting, expressionPath, mutationType, targetNode } = req.body;
      const editor = this.toolsData.tools.codeEditor;
      if (language) editor.language = language;
      if (mode) editor.mode = mode;
      if (code) {
        editor.code = code;
        editor.versionControl.push({
          versionId: crypto.randomUUID(),
          code,
          timestamp: new Date().toISOString(),
          commitMessage: `Update by ${userId}`
        });
      }
      if (runButton !== undefined) editor.runButton = runButton;
      if (enableAIHinting !== undefined) editor.enableAIHinting = enableAIHinting;
      if (expressionPath) editor.expressionPath = expressionPath;
      if (mutationType) editor.mutationType = mutationType;
      if (targetNode) editor.targetNode = targetNode;
      editor.output = this.executeCode(code, language); // Simulated execution
      this.validateData(this.toolsData);
      this.exchangeController.logComplianceEvent('code_editor_updated', userId, JSON.stringify({ language, mode }));
      res.status(200).json(editor);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  executeCode(code, language) {
    // Simulated execution; replace with actual runtime (e.g., Node.js for JS, Python interpreter)
    return `Executed ${language} code: ${code.slice(0, 50)}...`;
  }

  async configureDataVisualizer(req, res) {
    try {
      const { userId, dataSource, visualizationType, config, filters } = req.body;
      const visualizer = this.toolsData.tools.dataVisualizer;
      if (dataSource) visualizer.dataSource = dataSource;
      if (visualizationType) visualizer.visualizationType = visualizationType;
      if (config) visualizer.config = { ...visualizer.config, ...config };
      if (filters) visualizer.filters = filters;
      this.validateData(this.toolsData);
      this.exchangeController.logComplianceEvent('data_visualizer_configured', userId, JSON.stringify({ visualizationType }));
      res.status(200).json(visualizer);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async deployContract(req, res) {
    try {
      const { userId, contractCode, network, compilerVersion, constructorArgs } = req.body;
      const deployer = this.toolsData.tools.contractDeployer;
      deployer.contractCode = contractCode;
      deployer.network = network || 'testnet';
      deployer.compilerVersion = compilerVersion || 'latest';
      deployer.constructorArgs = constructorArgs || [];
      const deployment = {
        address: `0x${crypto.randomBytes(20).toString('hex')}`,
        timestamp: new Date().toISOString(),
        txHash: `0x${crypto.randomBytes(32).toString('hex')}`
      };
      deployer.deployments.push(deployment);
      this.validateData(this.toolsData);
      this.exchangeController.logComplianceEvent('contract_deployed', userId, JSON.stringify({ network, address: deployment.address }));
      res.status(201).json(deployment);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async testApi(req, res) {
    try {
      const { userId, endpoint, method, headers, body } = req.body;
      const tester = this.toolsData.tools.apiTester;
      tester.endpoint = endpoint;
      tester.method = method || 'GET';
      tester.headers = headers || {};
      tester.body = body || '';
      const request = {
        timestamp: new Date().toISOString(),
        responseStatus: 200, // Simulated
        responseBody: `Response from ${endpoint}` // Simulated
      };
      tester.requests.push(request);
      this.validateData(this.toolsData);
      this.exchangeController.logComplianceEvent('api_tested', userId, JSON.stringify({ endpoint, method }));
      res.status(201).json(request);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async addBreakpoint(req, res) {
    try {
      const { userId, lineNumber } = req.body;
      const editor = this.toolsData.tools.codeEditor;
      if (!editor.debugging.breakpoints.includes(lineNumber)) {
        editor.debugging.breakpoints.push(lineNumber);
      }
      this.validateData(this.toolsData);
      this.exchangeController.logComplianceEvent('breakpoint_added', userId, JSON.stringify({ lineNumber }));
      res.status(200).json(editor.debugging);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  async getToolData(req, res) {
    try {
      const { tool } = req.params;
      if (!this.toolsData.tools[tool]) throw new Error('Invalid tool');
      res.status(200).json(this.toolsData.tools[tool]);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }

  getToolsData() {
    return this.toolsData;
  }
}

module.exports = ToolsController;