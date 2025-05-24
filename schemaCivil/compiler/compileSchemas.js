// /compiler/compileSchemas.js
const fs = require('fs');
const path = require('path');
const Ajv = require('ajv');

const ajv = new Ajv({ allErrors: true, strict: false });

function validateSchemas(schemaDir) {
  const files = fs.readdirSync(schemaDir);
  files.forEach(file => {
    const filePath = path.join(schemaDir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      validateSchemas(filePath);
    } else if (file.endsWith('.json')) {
      const schema = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      try {
        ajv.compile(schema);
        console.log(`✅ VALID: ${filePath}`);
      } catch (err) {
        console.error(`❌ INVALID: ${filePath}`);
        console.error(err.errors || err);
      }
    }
  });
}

validateSchemas(path.resolve(__dirname, '../'));