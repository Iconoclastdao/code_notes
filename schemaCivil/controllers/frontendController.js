const Ajv = require('ajv');
const ajv = new Ajv({ allErrors: true, useDefaults: true });
const frontendSchema = require('../schema/frontend/frontend.schema.json');
const validate = ajv.compile(frontendSchema);

class FrontendController {
  constructor(exchangeController, dashboardsController) {
    this.exchangeController = exchangeController;
    this.dashboardsController = dashboardsController;
    this.frontendData = {
      components: [],
      layouts: [],
      themes: []
    };
  }

  validateData(data) {
    const valid = validate(data);
    if (!valid) throw new Error(`Validation failed: ${JSON.stringify(validate.errors, null, 2)}`);
    return valid;
  }

  addComponent(id, type, config) {
    const component = {
      id,
      type,
      config: { ...config, responsive: config.responsive ?? true },
      createdAt: new Date().toISOString()
    };
    this.frontendData.components.push(component);
    this.validateData(this.frontendData);
    this.exchangeController.logComplianceEvent('component_added', 'system', JSON.stringify({ id, type }));
    return component;
  }

  updateLayout(userId, layoutId, x, y, w, h) {
    const layout = this.frontendData.layouts.find(l => l.id === layoutId && l.user === userId);
    if (!layout) {
      const newLayout = { id: layoutId, user: userId, x, y, w, h, timestamp: new Date().toISOString() };
      this.frontendData.layouts.push(newLayout);
    } else {
      layout.x = x;
      layout.y = y;
      layout.w = w;
      layout.h = h;
      layout.timestamp = new Date().toISOString();
    }
    this.validateData(this.frontendData);
    this.dashboardsController.updateDashboardLayout(userId, layoutId, { x, y, w, h });
    return layout || this.frontendData.layouts.find(l => l.id === layoutId);
  }

  setTheme(userId, theme) {
    const existingTheme = this.frontendData.themes.find(t => t.user === userId);
    if (existingTheme) {
      existingTheme.theme = theme;
      existingTheme.timestamp = new Date().toISOString();
    } else {
      this.frontendData.themes.push({ user: userId, theme, timestamp: new Date().toISOString() });
    }
    this.validateData(this.frontendData);
    this.exchangeController.logComplianceEvent('theme_updated', userId, JSON.stringify({ theme }));
    return { user: userId, theme };
  }

  getFrontendData() {
    return this.frontendData;
  }
}

module.exports = FrontendController;