// scripts/generateControllers.js

const fs = require('fs');
const path = require('path');

const schemasDir = path.join(__dirname, '../schema');
const controllersDir = path.join(__dirname, '../controllers');

fs.readdirSync(schemasDir).forEach((file) => {
  if (file.endsWith('.schema.json')) {
    const resourceName = path.basename(file, '.schema.json');
    const controllerFileName = `${resourceName}Controller.js`;
    const controllerFilePath = path.join(controllersDir, controllerFileName);

    const controllerTemplate = `
// controllers/${controllerFileName}

const ${capitalize(resourceName)} = require('../models/${resourceName}Model');

// Define controller functions for ${resourceName} here

module.exports = {
  // create${capitalize(resourceName)},
  // getAll${capitalize(resourceName)}s,
  // get${capitalize(resourceName)}ById,
  // update${capitalize(resourceName)},
  // delete${capitalize(resourceName)},
};
`;

    fs.writeFileSync(controllerFilePath, controllerTemplate);
    console.log(`Generated controller: ${controllerFileName}`);
  }
});

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}