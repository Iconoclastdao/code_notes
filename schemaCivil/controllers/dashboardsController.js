const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const dashboardSchema = require('../schema/dashboard.schema.json');
const validate = ajv.compile(dashboardSchema);
const { v4: uuidv4 } = require('uuid');

class DashboardController {
  constructor(exchangeController, chainAdapter, marketController, datingController, nodeController, newsController, socialController, gamingController, daoController, crowdfundingController) {
    this.exchangeController = exchangeController;
    this.chainAdapter = chainAdapter;
    this.marketController = marketController;
    this.datingController = datingController;
    this.nodeController = nodeController;
    this.newsController = newsController;
    this.socialController = socialController;
    this.gamingController = gamingController;
    this.daoController = daoController;
    this.crowdfundingController = crowdfundingController;
    this.dashboards = new Map();
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) {
      throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    }
    return valid;
  }

  // Create a new dashboard
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
    return { id: dashboardId };
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

    // Validate data source
    await this.validateDataSource(widget.dataSource);
    dashboard.widgets.push(widget);

    // Trigger onWidgetAdd hook
    if (dashboard.transactionHooks?.onWidgetAdd) {
      await this.chainAdapter.executeHook(dashboard.transactionHooks.onWidgetAdd, { dashboardId, widgetId });
    }

    // Distribute karma wage
    await this.chainAdapter.distributeKarmaWage(dashboard.owner, dashboard.karmaWage);
    await this.chainAdapter.updateReputation(dashboard.owner, 0.5); // Example: +0.5 for widget creation
    this.exchangeController.logComplianceEvent('widget_added', dashboard.owner, JSON.stringify({ dashboardId, widgetId, type: widget.type }));
    return { id: widgetId };
  }

  // Validate data source
  async validateDataSource(dataSource) {
    const { type, id } = dataSource;
    try {
      switch (type) {
        case 'market':
          await this.marketController.getMarket(id);
          break;
        case 'dating':
          await this.datingController.getPlatform(id);
          break;
        case 'node':
          await this.nodeController.getNode(id);
          break;
        case 'news':
          await this.newsController.getNewsFeed(id);
          break;
        case 'social':
          await this.socialController.getSocialFeed(id);
          break;
        case 'gaming':
          await this.gamingController.getArena(id);
          break;
        case 'dao':
          await this.daoController.getDao(id);
          break;
        case 'crowdfunding':
          await this.crowdfundingController.getProject(id);
          break;
        case 'chain':
          await this.chainAdapter.validateContract(id);
          break;
        default:
          throw new Error('Invalid data source type');
      }
    } catch (error) {
      throw new Error(`Invalid data source: ${error.message}`);
    }
  }

  // Update dashboard layout
  async updateDashboardLayout(dashboardId, ownerId, layout) {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard || dashboard.owner !== ownerId) {
      throw new Error('Dashboard not found or unauthorized');
    }

    this.validateData({ layout });
    dashboard.layout = { ...layout, timestamp: new Date().toISOString() };
    this.exchangeController.logComplianceEvent('layout_updated', ownerId, JSON.stringify({ dashboardId, layout }));
    return dashboard.layout;
  }

  // Fetch widget data
  async fetchWidgetData(dashboardId, widgetId) {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error('Dashboard not found');
    }

    const widget = dashboard.widgets.find(w => w.id === widgetId);
    if (!widget) {
      throw new Error('Widget not found');
    }

    let data;
    switch (widget.dataSource.type) {
      case 'market':
        const market = await this.marketController.getMarket(widget.dataSource.id);
        data = widget.dataSource.query 
          ? market.market.offers.filter(o => o.tags?.includes(widget.dataSource.query))
          : market.market.offers;
        break;
      case 'dating':
        const platform = await this.datingController.getPlatform(widget.dataSource.id);
        data = widget.dataSource.query === 'profiles'
          ? platform.platform.profiles
          : platform.platform.matches.filter(m => m.status === widget.dataSource.query || m.status === 'accepted');
        break;
      case 'node':
        const node = await this.nodeController.getNode(widget.dataSource.id);
        data = widget.dataSource.query === 'entropy'
          ? await this.nodeController.fetchEntropy(widget.dataSource.id)
          : node.projects_owned;
        break;
      case 'news':
        const news = await this.newsController.getNewsFeed(widget.dataSource.id);
        data = widget.dataSource.query
          ? news.posts.filter(p => p.tags?.includes(widget.dataSource.query))
          : news.posts;
        break;
      case 'social':
        const social = await this.socialController.getSocialFeed(widget.dataSource.id);
        data = widget.dataSource.query
          ? social.posts.filter(p => p.tags?.includes(widget.dataSource.query))
          : social.posts;
        break;
      case 'gaming':
        const arena = await this.gamingController.getArena(widget.dataSource.id);
        data = widget.dataSource.query
          ? arena.games.filter(g => g.status === widget.dataSource.query)
          : arena.games;
        break;
      case 'dao':
        const dao = await this.daoController.getDao(widget.dataSource.id);
        data = widget.dataSource.query
          ? dao.proposals.filter(p => p.status === widget.dataSource.query)
          : dao.proposals;
        break;
      case 'crowdfunding':
        const project = await this.crowdfundingController.getProject(widget.dataSource.id);
        data = widget.dataSource.query
          ? project.funding.filter(f => f.status === widget.dataSource.query)
          : project.funding;
        break;
      case 'chain':
        data = await this.chainAdapter.queryContract(widget.dataSource.id, widget.dataSource.query);
        break;
      default:
        throw new Error('Unsupported data source');
    }

    // Distribute karma wage for data fetch
    await this.chainAdapter.distributeKarmaWage(dashboard.owner, dashboard.karmaWage);
    this.exchangeController.logComplianceEvent('widget_data_fetched', dashboard.owner, JSON.stringify({ dashboardId, widgetId }));
    return { widgetId, data };
  }

  // Share dashboard
  async shareDashboard(dashboardId, ownerId, targetAgent) {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard || dashboard.owner !== ownerId) {
      throw new Error('Dashboard not found or unauthorized');
    }

    // Trigger onDashboardShare hook
    if (dashboard.transactionHooks?.onDashboardShare) {
      await this.chainAdapter.executeHook(dashboard.transactionHooks.onDashboardShare, { dashboardId, targetAgent });
    }

    // Distribute karma wage
    await this.chainAdapter.distributeKarmaWage(dashboard.owner, dashboard.karmaWage);
    await this.chainAdapter.updateReputation(dashboard.owner, 0.3); // Example: +0.3 for sharing
    this.exchangeController.logComplianceEvent('dashboard_shared', ownerId, JSON.stringify({ dashboardId, targetAgent }));
    return { message: 'Dashboard shared successfully' };
  }

  // Propose a governance change
  async proposeGovernanceChange(dashboardId, ownerId, proposalData) {
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

    // Trigger onProposalSubmit hook
    if (dashboard.transactionHooks?.onProposalSubmit) {
      await this.chainAdapter.executeHook(dashboard.transactionHooks.onProposalSubmit, { dashboardId, proposalId });
    }

    await this.chainAdapter.submitProposal(dashboard.governance.votingContract, proposal);
    await this.chainAdapter.distributeKarmaWage(ownerId, dashboard.karmaWage);
    await this.chainAdapter.updateReputation(ownerId, 0.7); // Example: +0.7 for proposal
    this.exchangeController.logComplianceEvent('proposal_submitted', ownerId, JSON.stringify({ dashboardId, proposalId }));
    return { proposal_id: proposalId };
  }
}

module.exports = DashboardController;