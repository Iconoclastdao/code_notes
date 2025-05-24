const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const dashboardSchema = require('../schema/dashboard.schema.json');
const validate = ajv.compile(dashboardSchema);
const { v4: uuidv4 } = require('uuid');

class DashboardsModel {
  constructor(chainAdapter, exchangeController) {
    this.chainAdapter = chainAdapter;
    this.exchangeController = exchangeController;
    this.dashboards = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a dashboard
  async createDashboard(data) {
    this.validateData(data);
    const dashboardId = data.id || uuidv4();
    const dashboard = {
      ...data,
      id: dashboardId,
      type: 'dashboard',
      createdAt: new Date().toISOString()
    };

    // Verify soulbound ID
    const isValidSoulbound = await this.chainAdapter.verifySoulboundId(dashboard.owner, dashboard.soulboundId);
    if (!isValidSoulbound) {
      throw new Error(`Invalid soulbound ID for owner ${dashboard.owner}`);
    }

    this.dashboards.set(dashboardId, dashboard);
    await this.chainAdapter.registerDashboard(dashboardId, dashboard);
    this.exchangeController.logComplianceEvent('dashboard_created', dashboard.owner, JSON.stringify({ id: dashboardId, title: dashboard.title }));
    return dashboard;
  }

  // Get a dashboard by ID
  getDashboard(dashboardId) {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error('Dashboard not found');
    }
    return dashboard;
  }

  // Add a widget to a dashboard
  async addWidget(dashboardId, widgetData) {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error('Dashboard not found');
    }

    this.validateData({ widgets: [widgetData] });
    const widgetId = widgetData.id || uuidv4();
    const widget = {
      ...widgetData,
      id: widgetId,
      createdAt: new Date().toISOString()
    };

    dashboard.widgets.push(widget);
    await this.chainAdapter.updateDashboard(dashboardId, dashboard);
    this.exchangeController.logComplianceEvent('widget_added', dashboard.owner, JSON.stringify({ dashboardId, widgetId, type: widget.type }));
    return widget;
  }

  // Update dashboard layout
  async updateLayout(dashboardId, ownerId, layout) {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard || dashboard.owner !== ownerId) {
      throw new Error('Dashboard not found or unauthorized');
    }

    this.validateData({ layout });
    dashboard.layout = { ...layout, timestamp: new Date().toISOString() };
    await this.chainAdapter.updateDashboard(dashboardId, dashboard);
    this.exchangeController.logComplianceEvent('layout_updated', ownerId, JSON.stringify({ dashboardId, layout }));
    return dashboard.layout;
  }

  // Submit a governance proposal
  async submitProposal(dashboardId, ownerId, proposalData) {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard || dashboard.owner !== ownerId) {
      throw new Error('Dashboard not found or unauthorized');
    }

    const reputation = await this.chainAdapter.getReputation(ownerId);
    if (reputation < dashboard.governance.proposalThreshold) {
      throw new Error('Insufficient reputation to submit proposal');
    }

    const proposalId = proposalData.id || uuidv4();
    const proposal = {
      ...proposalData,
      id: proposalId,
      proposer: ownerId,
      createdAt: new Date().toISOString(),
      status: 'pending'
    };

    await this.chainAdapter.submitProposal(dashboard.governance.votingContract, proposal);
    this.exchangeController.logComplianceEvent('proposal_submitted', ownerId, JSON.stringify({ dashboardId, proposalId }));
    return proposal;
  }
}

module.exports = DashboardsModel;