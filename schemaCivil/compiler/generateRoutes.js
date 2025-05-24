// /compiler/generateRoutes.js
const fs = require('fs');
const path = require('path');

const apiSchemaPath = path.resolve(__dirname, '../api/sovereign-api.schema.json');
const outputPath = path.resolve(__dirname, '../server/generatedRoutes.js');

const schema = JSON.parse(fs.readFileSync(apiSchemaPath, 'utf-8'));
const endpoints = schema.api.endpoints;

const header = `const express = require('express');
const router = express.Router();\n`;

let body = '';

endpoints.forEach(ep => {
  const method = ep.method.toLowerCase();
  body += `
router.${method}('${ep.route}', async (req, res) => {
  // TODO: Add validation and handler logic
  res.json({ message: '${ep.name} called successfully' });
});
`;
});

const footer = `module.exports = router;`;

fs.writeFileSync(outputPath, header + body + footer);
console.log(`✅ Routes generated at: ${outputPath}`);