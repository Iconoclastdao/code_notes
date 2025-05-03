import { ethers, upgrades } from "hardhat";

async function main() {
  // 1. Deploy EntropyExpander
  const EntropyExpander = await ethers.getContractFactory("EntropyExpander");
  const entropyExpander = await EntropyExpander.deploy();
  await entropyExpander.waitForDeployment();
  console.log("EntropyExpander:", entropyExpander.target);

  // 2. Deploy KeccakBlackBoxEngines
  const KeccakBlackBoxEngine = await ethers.getContractFactory("KeccakBlackBoxEngine");
  const engineA = await KeccakBlackBoxEngine.deploy(ethers.parseEther("0.001"), 1000);
  await engineA.waitForDeployment();
  const engineB = await KeccakBlackBoxEngine.deploy(ethers.parseEther("0.001"), 1000);
  await engineB.waitForDeployment();
  const engineC = await KeccakBlackBoxEngine.deploy(ethers.parseEther("0.001"), 1000);
  await engineC.waitForDeployment();
  console.log("EngineA:", engineA.target);
  console.log("EngineB:", engineB.target);
  console.log("EngineC:", engineC.target);

  // Set expander for each engine
  await (await engineA.setEntropyExpander(entropyExpander.target)).wait();
  await (await engineB.setEntropyExpander(entropyExpander.target)).wait();
  await (await engineC.setEntropyExpander(entropyExpander.target)).wait();

  // 3. Deploy EntropyCoordinator
  const EntropyCoordinator = await ethers.getContractFactory("EntropyCoordinator");
  const entropyCoordinator = await EntropyCoordinator.deploy(engineA.target, engineB.target, engineC.target);
  await entropyCoordinator.waitForDeployment();
  console.log("EntropyCoordinator:", entropyCoordinator.target);

  // 4. Deploy IconoclastToken (UUPS Proxy)
  const IconoclastToken = await ethers.getContractFactory("IconoclastToken");
  const token = await upgrades.deployProxy(IconoclastToken, [ethers.ZeroAddress], { initializer: "initialize" });
  await token.waitForDeployment();
  console.log("IconoclastToken (proxy):", token.target);

  // 5. Deploy BadgeNFT (UUPS Proxy)
  const BadgeNFT = await ethers.getContractFactory("BadgeNFT");
  const badgeNFT = await upgrades.deployProxy(BadgeNFT, [ethers.ZeroAddress], { initializer: "initialize" });
  await badgeNFT.waitForDeployment();
  console.log("BadgeNFT (proxy):", badgeNFT.target);

  // 6. Deploy AgentNFT (UUPS Proxy)
  const AgentNFT = await ethers.getContractFactory("AgentNFT");
  const agentNFT = await upgrades.deployProxy(AgentNFT, [ethers.ZeroAddress], { initializer: "initialize" });
  await agentNFT.waitForDeployment();
  console.log("AgentNFT (proxy):", agentNFT.target);

  // 7. Deploy Treasury (UUPS Proxy)
  const Treasury = await ethers.getContractFactory("Treasury");
  const treasury = await upgrades.deployProxy(Treasury, [token.target, ethers.ZeroAddress], { initializer: "initialize" });
  await treasury.waitForDeployment();
  console.log("Treasury (proxy):", treasury.target);

  // 8. Deploy Escrow (UUPS Proxy)
  const Escrow = await ethers.getContractFactory("Escrow");
  const escrow = await upgrades.deployProxy(Escrow, [token.target, ethers.ZeroAddress], { initializer: "initialize" });
  await escrow.waitForDeployment();
  console.log("Escrow (proxy):", escrow.target);

  // 9. Deploy Governance (UUPS Proxy)
  const Governance = await ethers.getContractFactory("Governance");
  const governance = await upgrades.deployProxy(Governance, [badgeNFT.target, ethers.ZeroAddress], { initializer: "initialize" });
  await governance.waitForDeployment();
  console.log("Governance (proxy):", governance.target);

  // 10. Deploy ModuleRegistry (UUPS Proxy)
  const ModuleRegistry = await ethers.getContractFactory("ModuleRegistry");
  const moduleRegistry = await upgrades.deployProxy(ModuleRegistry, [governance.target, ethers.ZeroAddress], { initializer: "initialize" });
  await moduleRegistry.waitForDeployment();
  console.log("ModuleRegistry (proxy):", moduleRegistry.target);

  // 11. Deploy IconoclastProtocol (not upgradeable)
  const IconoclastProtocol = await ethers.getContractFactory("IconoclastProtocol");
  const protocol = await IconoclastProtocol.deploy(governance.target);
  await protocol.waitForDeployment();
  console.log("IconoclastProtocol:", protocol.target);

  // 12. Set protocol addresses in all contracts (owner only)
  // You may need to impersonate the owner or use the same deployer for all
  await (await token.setGovernance(protocol.target)).wait();
  await (await badgeNFT.setGovernance(protocol.target)).wait();
  await (await agentNFT.setGovernance(protocol.target)).wait();
  await (await treasury.setGovernance(protocol.target)).wait();
  await (await escrow.setGovernance(protocol.target)).wait();
  await (await governance.setGovernance(protocol.target)).wait();
  await (await moduleRegistry.setGovernance(protocol.target)).wait();

  // 13. Initialize protocol with contract addresses if needed (not shown in your code)
  // e.g. protocol.initialize(token.target, badgeNFT.target, ...)

  console.log("Deployment complete!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
