// /compiler/generateFrontendComponents.js
const fs = require('fs');
const path = require('path');

const frontendSchema = require('../frontend/frontend.schema.json'); // You'll create this
const outputDir = path.resolve(__dirname, '../frontend/components/generated');
if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

frontendSchema.components.forEach(component => {
  const compName = component.name;
  const props = component.props || [];

  const propDeclarations = props.map(p => `${p.name}`).join(', ');
  const jsxProps = props.map(p => `${p.name}={${p.name}}`).join(' ');

  const compString = `
import React from 'react';

const ${compName} = ({ ${propDeclarations} }) => {
  return (
    <div className="${component.className || ''}">
      {/* TODO: Implement ${compName} UI */}
      <p>${compName} loaded</p>
    </div>
  );
};

export default ${compName};
  `;

  fs.writeFileSync(path.join(outputDir, `${compName}.jsx`), compString);
  console.log(`✅ Generated component: ${compName}`);
});