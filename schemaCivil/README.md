# JSONFlow

**JSONFlow** is a powerful, schema-driven Domain-Specific Language (DSL) platform for orchestrating interoperable workflows across diverse domains, including blockchain, artificial intelligence (AI), natural language processing (NLP), quantum computing, gaming, and user interface (UI) development. By leveraging JSON schemas, JSONFlow enables developers to define complex workflows that integrate cutting-edge technologies, automate code generation, and ensure secure, modular, and extensible application logic.

---

## Project Overview

JSONFlow provides a unified framework for creating workflows that combine:

- **Blockchain Operations**: Smart contract deployment, token minting, and cryptographic signing/verification.  
- **AI and Machine Learning**: Inference, training, classification, and embeddings with support for multiple models.  
- **Natural Language Processing**: Advanced NLP with semantic constructs, analogy mapping, and multimodal input (text, voice).  
- **Quantum Computing**: Quantum circuits, gates, and algorithms like Grover and Shor.  
- **Gaming**: Rendering, physics, multiplayer synchronization, and animations for game engines like Unity and Godot.  
- **UI Development**: Framework-agnostic UI components with game-specific properties (e.g., HUD, VR interfaces).  

The core of JSONFlow is the `jsonflow-workflow.schema.json`, a comprehensive JSON Schema that defines workflow structures, including inputs, outputs, steps, and policies. Compiler scripts validate schemas and generate controllers, routes, and frontend components, ensuring consistency and reducing manual coding.

---

## Key Features

- **Modular DSL**: Define workflows with a flexible, extensible schema supporting conditional logic, parallel execution, and error handling.  
- **Cross-Domain Integration**: Seamlessly combine blockchain, AI, NLP, quantum computing, and gaming in a single workflow.  
- **Schema-Driven Automation**: Generate controllers, routes, and React components from schemas, minimizing boilerplate code.  
- **Security**: Role-based access control, cryptographic attestation, and execution policies for secure workflows.  
- **Extensibility**: Support for custom steps and subworkflows, with recursive schema processing for scalability.  

---

## Installation

### Prerequisites

- **Node.js**: Version 16 or higher.  
- **npm**: Version 8 or higher.  
- **Code Editor**: A modern code editor (e.g., VS Code) for editing schemas and scripts.

### Setup

```bash
# Clone the Repository:
git clone https://github.com/your-org/jsonflow.git
cd jsonflow

# Install Dependencies:
npm install

# Validate Schemas:
npm run compile

# Generate Code:
npm run generate-controllers
npm run generate-routes
npm run generate-frontend

# Start the Server:
npm start

# Run Tests (Optional):
npm test
```

---

## Project Structure

```
├── README.md
├── app.js
├── compiler
│   ├── compileSchemas.js
│   ├── generateControllers.js
│   ├── generateFrontendComponents.js
│   └── generateRoutes.js
├── controllers
│   ├── agentController.js
│   ├── apiController.js
│   ├── casinoController.js
│   └── ...
├── logs
│   ├── compileSchemas.log
│   └── ...
├── models
│   ├── apiModel.js
│   ├── casinoModel.js
│   └── ...
├── routes
│   └── generatedRoutes.js
├── schema
│   ├── agent
│   │   ├── agent.schema.json
│   │   └── ...
│   ├── api
│   │   └── sovereign-api.schema.json
│   ├── dashboards
│   │   ├── natural-language.schema.json
│   │   └── ...
│   ├── rituals
│   │   ├── ritual.schema.json
│   │   └── ...
│   ├── sovereign
│   │   ├── jsonflow-workflow.schema.json
│   │   ├── module-wrapper.schema.json
│   │   └── ...
│   ├── token
│   │   └── token.schema.json
│   └── ...
├── scripts
│   └── tests
└── server.js
```

---

## Schema Directory

The schema directory is the heart of JSONFlow, containing:

- **Domain-Specific Schemas**: Subdirectories like `agent`, `casino`, `dashboards`, and `token` define schemas for specific domains.  
- **Sovereign Schemas**: The `sovereign` subdirectory includes cross-cutting schemas like `jsonflow-workflow.schema.json`.  
- **Rituals**: The `rituals` subdirectory defines ritual-related processes (e.g., consensus checks, signal initiation).

See `schema/README.md` for detailed schema documentation.

---

## Usage

### Defining a Workflow

```json
{
  "$schema": "../sovereign/jsonflow-workflow.schema.json",
  "id": "example-workflow",
  "title": "NLP to Blockchain Workflow",
  "schema": {
    "inputs": { "userInput": { "type": "string" } },
    "outputs": { "transactionId": { "type": "string" } }
  },
  "steps": [
    {
      "type": "ai_nlp_process",
      "id": "nlp-step",
      "model": "gpt-4",
      "input": "{userInput}",
      "output": "parsedIntent"
    },
    {
      "type": "blockchain_operation",
      "id": "mint-nft",
      "chain": "ethereum",
      "action": "mint",
      "parameters": {
        "recipient": "0x123...",
        "metadata": "{parsedIntent}"
      },
      "output": "transactionId"
    }
  ]
}
```

Save as: `schema/example/example-workflow.schema.json`

```bash
npm run compile
npm run generate-controllers
```

### Testing the Workflow

```bash
npm start
```

Use a tool like Postman:

- Endpoint: `POST /api/example`
- Payload:
```json
{ "userInput": "Mint an NFT" }
```

---

## Generating Frontend Components

```bash
npm run generate-frontend
```

This generates React components in:

```
frontend/components/generated
```

---

## Example Workflow

```json
{
  "$schema": "../sovereign/jsonflow-workflow.schema.json",
  "id": "game-workflow",
  "title": "Game and Blockchain Workflow",
  "schema": {
    "inputs": { "playerInput": { "type": "string" } },
    "outputs": {
      "gameState": { "type": "object" },
      "txId": { "type": "string" }
    }
  },
  "steps": [
    {
      "type": "ai_nlp_process",
      "id": "parse-input",
      "model": "bert",
      "input": "{playerInput}",
      "output": "intent"
    },
    {
      "type": "game_render",
      "id": "render-scene",
      "engine": "unity",
      "scene": "main-scene",
      "parameters": { "action": "{intent}" },
      "output": "gameState"
    },
    {
      "type": "blockchain_operation",
      "id": "record-action",
      "chain": "polygon",
      "action": "call",
      "contract": "0x456...",
      "method": "recordAction",
      "parameters": { "state": "{gameState}" },
      "output": "txId"
    }
  ]
}
```

```bash
npm run compile
npm run generate-controllers
npm run generate-routes
```

Test with:
```json
POST /api/game
{
  "playerInput": "Move player to position (10, 20)"
}
```

---

## Development

### Adding a New Domain

```bash
mkdir schema/new-domain
touch schema/new-domain/new-domain.schema.json
```

Define the schema, then:

```bash
npm run generate-controllers
```

Creates:

- `controllers/newDomainController.js`
- `models/newDomainModel.js`

---

## Running Tests

Install Jest:

```bash
npm install --save-dev jest
```

Create test files in:

```
scripts/tests/
```

Run:

```bash
npm test
```

---

## Debugging

Check logs:

- `logs/compileSchemas.log`
- `logs/generateControllers.log`

---

## Contributing

1. Fork the repository.  
2. Create a feature branch: `git checkout -b feature/new-feature`  
3. Commit: `git commit -m "Add new feature"`  
4. Push: `git push origin feature/new-feature`  
5. Open a pull request.

Follow the Code of Conduct and ensure tests pass.

---

## License

MIT License – See the `LICENSE` file.

---

## Contact

Questions/support:  
📧 support@jsonflow.org  
📂 GitHub Issues: [Open an issue](https://github.com/your-org/jsonflow/issues)