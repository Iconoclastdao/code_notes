
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";


interface IEntropyEngine {
    function getEntropy(uint256 seed) external view returns (bytes32);
}
interface IModuleRegistry {
    function isWhitelisted(address module) external view returns (bool);
}

interface IWalletModule {
    function supportedFunctions() external view returns (bytes4[] memory);
}

contract CapsuleAgent is
    ERC721,
    AccessControl,
    Pausable,
    ReentrancyGuard
{
    using Address for address;


    // --- Roles ---
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // --- External dependencies ---
    IModuleRegistry public immutable moduleRegistry;
    address public immutable walletImplementation;
    address public immutable oracleImplementation;
    IERC20 public immutable govToken;
    IEntropyEngine public immutable entropyEngine;

    // --- Storage ---
    uint256 private _tokenIds;
    uint256 private _betIds;

    struct AgentDNA {
        bytes32 dnaHash;
        uint256 fitness;
        address[] modules;
        address wallet;
        address oracle;
    }
    mapping(uint256 => AgentDNA) public agentDNAs;
    mapping(uint256 => bool) public agentExists;

    /// @notice The address where minting fees are sent.
    address public feeVault;

    /// @notice The fee required to mint a new agent.
    /// @dev Can be updated by an admin via `setMintFee`.
    uint256 public mintFee = 0.01 ether;

    // --- Betting ---
    enum BetStatus { Open, Accepted, Settled }
    struct Bet {
        address creator;
        address acceptor;
        uint256 creatorAgentId;
        uint256 acceptorAgentId;
        uint256 amount;
        uint256 createdAt;
        uint256 acceptedAt;
        uint256 settledAt;
        address winner;
        bytes32 entropyAtSettlement;
        BetStatus status;
    }
    mapping(uint256 => Bet) public bets;

    // --- Events ---
    event AgentCreated(uint256 indexed tokenId, address owner, bytes32 dnaHash, address wallet, address oracle);
    event BetCreated(uint256 indexed betId, address indexed creator, uint256 creatorAgentId, uint256 amount);
    event BetAccepted(uint256 indexed betId, address indexed acceptor, uint256 acceptorAgentId);
    event BetSettled(uint256 indexed betId, address indexed winner, bytes32 entropy);
    event MintFeeUpdated(uint256 newFee);
    event FeeVaultUpdated(address newFeeVault);


    constructor(
        address _moduleRegistry,
        address _walletImplementation,
        address _oracleImplementation,
        address _govToken,
        address _entropyEngine,
        address initialAdmin,
        address _feeVault
    )
        ERC721("CapsuleAgent", "CAG")
    {
        
        require(_feeVault != address(0), "Invalid feeVault");
        require(initialAdmin != address(0), "Invalid admin");

        moduleRegistry = IModuleRegistry(_moduleRegistry);
        walletImplementation = _walletImplementation;
        oracleImplementation = _oracleImplementation;
        govToken = IERC20(_govToken);
        entropyEngine = IEntropyEngine(_entropyEngine);
        feeVault = _feeVault;

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ADMIN_ROLE, initialAdmin);
    }

    /// @notice Modifier to check if an address is a contract.



    /// @notice Mints a new agent with the specified modules.
    /// @param modules The list of whitelisted modules to attach to the agent.
    function mintAgent(address[] calldata modules) external payable nonReentrant whenNotPaused {
        require(msg.value >= mintFee, "Insufficient mint fee");
        require(modules.length > 0, "No modules provided");

        // Validate modules
        for (uint256 i = 0; i < modules.length; i++) {
            require(moduleRegistry.isWhitelisted(modules[i]), "Module not whitelisted");
        }

        uint256 tokenId = _tokenIds++;

        // Clone wallet and oracle
        address wallet = Clones.clone(walletImplementation);
        address oracle = Clones.clone(oracleImplementation);

        // Generate DNA hash
        bytes32 dnaHash = entropyEngine.getEntropy(tokenId);

        // Store agent data
        agentDNAs[tokenId] = AgentDNA({
            dnaHash: dnaHash,
            fitness: 0,
            modules: modules,
            wallet: wallet,
            oracle: oracle
        });
        agentExists[tokenId] = true;

        // Mint NFT
        _safeMint(msg.sender, tokenId);

        // Transfer fee to vault
        Address.sendValue(payable(feeVault), msg.value);

        emit AgentCreated(tokenId, msg.sender, dnaHash, wallet, oracle);
    }

    /// @notice Sets the minting fee for new agents.
    /// @param newFee The new minting fee in wei.
    function setMintFee(uint256 newFee) external onlyRole(ADMIN_ROLE) {
        require(newFee > 0, "Fee must be greater than zero");
        mintFee = newFee;
        emit MintFeeUpdated(newFee);
    }

    /// @notice Sets the fee vault address.
    /// @param newFeeVault The new fee vault address.
    function setFeeVault(address newFeeVault) external onlyRole(ADMIN_ROLE) {
        require(newFeeVault != address(0), "Invalid feeVault");
        feeVault = newFeeVault;
        emit FeeVaultUpdated(newFeeVault);
    }

    /// @notice Pauses the contract, disabling certain functions.
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
        emit Paused(msg.sender);
    }

    /// @notice Unpauses the contract, re-enabling functions.
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
        emit Unpaused(msg.sender);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, AccessControl) returns (bool) {
        return
            ERC721.supportsInterface(interfaceId) ||
            AccessControl.supportsInterface(interfaceId) ||
            super.supportsInterface(interfaceId);
    }

    receive() external payable {
        Address.sendValue(payable(feeVault), msg.value);
    }
}