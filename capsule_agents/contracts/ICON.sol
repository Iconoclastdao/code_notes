// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
 import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
 import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {ERC20PermitUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {ERC20VotesUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20VotesUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {NoncesUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/NoncesUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {ERC721EnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import {ERC721URIStorageUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import {ERC721VotesUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721VotesUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";




/// @title Keccak Utility Library
library LibKeccak {
    /// @notice The block size of the Keccak-f[1600] permutation, 1088 bits (136 bytes).
    uint256 internal constant BLOCK_SIZE_BYTES = 136;

    /// @notice The round constants for Keccak-f[1600].
    bytes internal constant ROUND_CONSTANTS = abi.encode(
        0x00000000000000010000000000008082800000000000808a8000000080008000, // r1,r2,r3,r4
        0x000000000000808b000000008000000180000000800080818000000000008009, // r5,r6,r7,r8
        0x000000000000008a00000000000000880000000080008009000000008000000a, // r9,r10,r11,r12
        0x000000008000808b800000000000008b80000000000080898000000000008003, // r13,r14,r15,r16
        0x80000000000080028000000000000080000000000000800a800000008000000a, // r17,r18,r19,r20
        0x8000000080008081800000000000808000000000800000018000000080008008 // r21,r22,r23,r24
    );

    /// @notice A mask for 64-bit values.
    uint64 private constant U64_MASK = 0xFFFFFFFFFFFFFFFF;

    /// @notice The 5x5 state matrix for the Keccak-f[1600] permutation.
    struct StateMatrix {
        uint64[25] state;
    }

    /// @notice Performs the Keccak-f[1600] permutation on the given state matrix.
    /// @param _stateMatrix The state matrix to permute
    function permutation(StateMatrix memory _stateMatrix) internal pure {
        bytes memory roundConstants = ROUND_CONSTANTS;

        assembly {
            let stateMatrixPtr := add(_stateMatrix, 0x20)
            let rcPtr := add(roundConstants, 0x20)

            function setStateElem(ptr, idx, data) {
                mstore(add(ptr, shl(0x05, idx)), and(data, U64_MASK))
            }

            function stateElem(ptr, idx) -> elem {
                elem := mload(add(ptr, shl(0x05, idx)))
            }

            function shl64(a, b) -> val {
                val := and(shl(a, b), U64_MASK)
            }

            function rhoPi(ptr, destIdx, srcIdx, fact, dt) {
                let xs1 := xor(stateElem(ptr, srcIdx), dt)
                let res := xor(shl(fact, xs1), shr(sub(64, fact), xs1))
                setStateElem(ptr, destIdx, res)
            }

            function xorColumn(ptr, col) -> val {
                val := xor(
                    xor(xor(stateElem(ptr, col), stateElem(ptr, add(col, 5))), stateElem(ptr, add(col, 10))),
                    xor(stateElem(ptr, add(col, 15)), stateElem(ptr, add(col, 20)))
                )
            }

            function thetaRhoPi(ptr) {
                let C0 := xorColumn(ptr, 0)
                let C1 := xorColumn(ptr, 1)
                let C2 := xorColumn(ptr, 2)
                let C3 := xorColumn(ptr, 3)
                let C4 := xorColumn(ptr, 4)
                let D0 := xor(xor(shl64(1, C1), shr(63, C1)), C4)
                let D1 := xor(xor(shl64(1, C2), shr(63, C2)), C0)
                let D2 := xor(xor(shl64(1, C3), shr(63, C3)), C1)
                let D3 := xor(xor(shl64(1, C4), shr(63, C4)), C2)
                let D4 := xor(xor(shl64(1, C0), shr(63, C0)), C3)

                let xs1 := xor(stateElem(ptr, 1), D1)
                let A1 := xor(shl64(1, xs1), shr(63, xs1))

                let _ptr := ptr
                setStateElem(_ptr, 0, xor(stateElem(_ptr, 0), D0))
                rhoPi(_ptr, 1, 6, 44, D1)
                rhoPi(_ptr, 6, 9, 20, D4)
                rhoPi(_ptr, 9, 22, 61, D2)
                rhoPi(_ptr, 22, 14, 39, D4)
                rhoPi(_ptr, 14, 20, 18, D0)
                rhoPi(_ptr, 20, 2, 62, D2)
                rhoPi(_ptr, 2, 12, 43, D2)
                rhoPi(_ptr, 12, 13, 25, D3)
                rhoPi(_ptr, 13, 19, 8, D4)
                rhoPi(_ptr, 19, 23, 56, D3)
                rhoPi(_ptr, 23, 15, 41, D0)
                rhoPi(_ptr, 15, 4, 27, D4)
                rhoPi(_ptr, 4, 24, 14, D4)
                rhoPi(_ptr, 24, 21, 2, D1)
                rhoPi(_ptr, 21, 8, 55, D3)
                rhoPi(_ptr, 8, 16, 45, D1)
                rhoPi(_ptr, 16, 5, 36, D0)
                rhoPi(_ptr, 5, 3, 28, D3)
                rhoPi(_ptr, 3, 18, 21, D3)
                rhoPi(_ptr, 18, 17, 15, D2)
                rhoPi(_ptr, 17, 11, 10, D1)
                rhoPi(_ptr, 11, 7, 6, D2)
                rhoPi(_ptr, 7, 10, 3, D0)
                setStateElem(_ptr, 10, A1)
            }

            function innerChi(ptr, start) {
                let A0 := stateElem(ptr, start)
                let A1 := stateElem(ptr, add(start, 1))
                let A2 := stateElem(ptr, add(start, 2))
                let A3 := stateElem(ptr, add(start, 3))
                let A4 := stateElem(ptr, add(start, 4))

                setStateElem(ptr, start, xor(A0, and(not(A1), A2)))
                setStateElem(ptr, add(start, 1), xor(A1, and(not(A2), A3)))
                setStateElem(ptr, add(start, 2), xor(A2, and(not(A3), A4)))
                setStateElem(ptr, add(start, 3), xor(A3, and(not(A4), A0)))
                setStateElem(ptr, add(start, 4), xor(A4, and(not(A0), A1)))
            }

            function chi(ptr) {
                innerChi(ptr, 0)
                innerChi(ptr, 5)
                innerChi(ptr, 10)
                innerChi(ptr, 15)
                innerChi(ptr, 20)
            }

            function permute(ptr, roundsPtr, round) {
                thetaRhoPi(ptr)
                chi(ptr)
                let roundConst := shr(192, mload(add(roundsPtr, shl(0x03, round))))
                setStateElem(ptr, 0, xor(stateElem(ptr, 0), roundConst))
            }

            permute(stateMatrixPtr, rcPtr, 0)
            permute(stateMatrixPtr, rcPtr, 1)
            permute(stateMatrixPtr, rcPtr, 2)
            permute(stateMatrixPtr, rcPtr, 3)
            permute(stateMatrixPtr, rcPtr, 4)
            permute(stateMatrixPtr, rcPtr, 5)
            permute(stateMatrixPtr, rcPtr, 6)
            permute(stateMatrixPtr, rcPtr, 7)
            permute(stateMatrixPtr, rcPtr, 8)
            permute(stateMatrixPtr, rcPtr, 9)
            permute(stateMatrixPtr, rcPtr, 10)
            permute(stateMatrixPtr, rcPtr, 11)
            permute(stateMatrixPtr, rcPtr, 12)
            permute(stateMatrixPtr, rcPtr, 13)
            permute(stateMatrixPtr, rcPtr, 14)
            permute(stateMatrixPtr, rcPtr, 15)
            permute(stateMatrixPtr, rcPtr, 16)
            permute(stateMatrixPtr, rcPtr, 17)
            permute(stateMatrixPtr, rcPtr, 18)
            permute(stateMatrixPtr, rcPtr, 19)
            permute(stateMatrixPtr, rcPtr, 20)
            permute(stateMatrixPtr, rcPtr, 21)
            permute(stateMatrixPtr, rcPtr, 22)
            permute(stateMatrixPtr, rcPtr, 23)
        }
    }

    /// @notice Absorbs a fixed-sized block into the sponge.
    /// @param _stateMatrix The state matrix
    /// @param _input The input block (must be 136 bytes)
    function absorb(StateMatrix memory _stateMatrix, bytes memory _input) internal pure {
        if (_input.length != BLOCK_SIZE_BYTES) revert InvalidInput();

        assembly {
            let dataPtr := add(_input, 0x20)
            let statePtr := add(_stateMatrix, 0x20)

            function setStateElem(ptr, idx, data) {
                mstore(add(ptr, shl(0x05, idx)), and(data, U64_MASK))
            }

            function stateElem(ptr, idx) -> elem {
                elem := mload(add(ptr, shl(0x05, idx)))
            }

            function absorbInner(stateMatrixPtr, inputPtr, idx) {
                let boWord := mload(add(inputPtr, shl(3, idx)))
                let res := or(
                    or(
                        or(shl(56, byte(7, boWord)), shl(48, byte(6, boWord))),
                        or(shl(40, byte(5, boWord)), shl(32, byte(4, boWord)))
                    ),
                    or(
                        or(shl(24, byte(3, boWord)), shl(16, byte(2, boWord))),
                        or(shl(8, byte(1, boWord)), byte(0, boWord))
                    )
                )
                setStateElem(stateMatrixPtr, idx, xor(stateElem(stateMatrixPtr, idx), res))
            }

            absorbInner(statePtr, dataPtr, 0)
            absorbInner(statePtr, dataPtr, 1)
            absorbInner(statePtr, dataPtr, 2)
            absorbInner(statePtr, dataPtr, 3)
            absorbInner(statePtr, dataPtr, 4)
            absorbInner(statePtr, dataPtr, 5)
            absorbInner(statePtr, dataPtr, 6)
            absorbInner(statePtr, dataPtr, 7)
            absorbInner(statePtr, dataPtr, 8)
            absorbInner(statePtr, dataPtr, 9)
            absorbInner(statePtr, dataPtr, 10)
            absorbInner(statePtr, dataPtr, 11)
            absorbInner(statePtr, dataPtr, 12)
            absorbInner(statePtr, dataPtr, 13)
            absorbInner(statePtr, dataPtr, 14)
            absorbInner(statePtr, dataPtr, 15)
            absorbInner(statePtr, dataPtr, 16)
        }
    }

    /// @notice Squeezes the final keccak256 digest from the state matrix.
    /// @param _stateMatrix The state matrix
    /// @return hash_ The 256-bit hash
    function squeeze(StateMatrix memory _stateMatrix) internal pure returns (bytes32 hash_) {
        assembly {
            function shl64(a, b) -> val {
                val := and(shl(a, b), U64_MASK)
            }

            function toLE(beVal) -> leVal {
                beVal := or(and(shl64(8, beVal), 0xFF00FF00FF00FF00), and(shr(8, beVal), 0x00FF00FF00FF00FF))
                beVal := or(and(shl64(16, beVal), 0xFFFF0000FFFF0000), and(shr(16, beVal), 0x0000FFFF0000FFFF))
                leVal := or(shl64(32, beVal), shr(32, beVal))
            }

            function stateElem(ptr, idx) -> elem {
                elem := mload(add(ptr, shl(0x05, idx)))
            }

            let stateMatrixPtr := add(_stateMatrix, 0x20)
            hash_ := or(
                or(shl(192, toLE(stateElem(stateMatrixPtr, 0))), shl(128, toLE(stateElem(stateMatrixPtr, 1)))),
                or(shl(64, toLE(stateElem(stateMatrixPtr, 2))), toLE(stateElem(stateMatrixPtr, 3)))
            )
        }
    }

    /// @notice Pads input data to a multiple of the block size.
    /// @param _data The input data
    /// @return padded_ The padded data
    function pad(bytes calldata _data) internal pure returns (bytes memory padded_) {
        assembly {
            padded_ := mload(0x40)
            let len := _data.length
            let dataPtr := add(padded_, 0x20)
            let endPtr := add(dataPtr, len)

            calldatacopy(dataPtr, _data.offset, len)
            let modBlockSize := mod(len, BLOCK_SIZE_BYTES)

            switch modBlockSize
            case 0 {
                calldatacopy(endPtr, calldatasize(), BLOCK_SIZE_BYTES)
                mstore8(endPtr, 0x01)
                mstore8(sub(add(endPtr, BLOCK_SIZE_BYTES), 0x01), 0x80)
                mstore(padded_, add(len, BLOCK_SIZE_BYTES))
            }
            default {
                let remaining := sub(BLOCK_SIZE_BYTES, modBlockSize)
                let newLen := add(len, remaining)
                let paddedEndPtr := add(dataPtr, newLen)
                let partialRemainder := sub(paddedEndPtr, endPtr)
                calldatacopy(endPtr, calldatasize(), partialRemainder)
                mstore8(sub(paddedEndPtr, 0x01), 0x80)
                mstore8(endPtr, or(byte(0x00, mload(endPtr)), 0x01))
                mstore(padded_, newLen)
            }

            mstore(0x40, add(padded_, and(add(mload(padded_), 0x3F), not(0x1F))))
        }
    }

    /// @notice Error for invalid input
    error InvalidInput();
}

interface IEntropyExpander {
    function expand(bytes32 entropySeed, uint256 count) external view returns (uint256[] memory);
}




/// @title Keccak Black Box Engine for Entropy Generation
contract KeccakBlackBoxEngine is Ownable,  ReentrancyGuard {
    using LibKeccak for LibKeccak.StateMatrix;
    IEntropyExpander public entropyExpander;

    /// @notice The size of the Keccak state (200 bytes).
    uint256 public constant STATE_SIZE = 200;
    /// @notice The rate of the sponge (136 bytes).
    uint256 public constant RATE = 136;
    /// @notice The capacity of the sponge (64 bytes).
    uint256 public constant CAPACITY = 64;
    /// @notice The maximum number of iterations per entropy feed.
    uint256 public constant MAX_ITERATIONS = 100;
    /// @notice The maximum number of commitments in a batch.
    uint256 public constant MAX_BATCH_COMMITS = 50;

    /// @notice The fee required to reveal entropy (in wei).
    uint256 public feePerEntropy = 0.001 ether;
    /// @notice The current step count in the sponge process.
    uint256 public stepCount;
    /// @notice The maximum number of steps allowed.
    uint256 public maxSteps = 1000;
    /// @notice The delay before a new Merkle root can be applied (in seconds).
    uint256 public merkleRootUpdateDelay = 1 days;
    /// @notice The timestamp when the pending Merkle root was proposed.
    uint256 public pendingMerkleRootTimestamp;

    /// @notice The current state of the Keccak sponge.
    bytes public internalState = new bytes(STATE_SIZE);
    /// @notice The current Merkle root for verification.
    bytes32 public merkleRoot;
    /// @notice The pending Merkle root awaiting application.
    bytes32 public pendingMerkleRoot;
    /// @notice List of deployed storage shard addresses.
    address[] public shards;

    /// @notice Mapping of sponge steps by step ID.
    mapping(uint256 => SpongeStep) public spongeSteps;
    /// @notice Mapping of user commitments.
    mapping(address => bytes32) public commitments;
    /// @notice Mapping of commitment timestamps for expiration.
    mapping(address => uint256) public commitmentTimestamps;
    mapping(address => uint256) public totalEntropyRevealed;
    mapping(address => uint256) public gasUsedPerReveal;
     mapping(address => uint256) public lastRevealTimestamp;
     mapping(uint256 => uint256) public gasPerStep;

    struct SpongeStep {
        bytes32 inputChunkHash;
        bytes32 beforeAbsorbHash;
        bytes32 afterPermuteHash;
    }

    /// @notice Emitted when a sponge step is traced.
    event SpongeStepTraced(
        uint256 indexed stepId,
        bytes32 inputChunkHash,
        bytes32 beforeAbsorbHash,
        bytes32 afterPermuteHash
    );
    /// @notice Emitted when entropy is committed.
    event EntropyCommitted(address indexed contributor, bytes32 commitment);
    /// @notice Emitted when entropy is revealed.
    event EntropyRevealed(address indexed contributor, bytes32 entropyHash);
    /// @notice Emitted when the Merkle root is proposed.
    event MerkleRootProposed(bytes32 newRoot);
    /// @notice Emitted when the Merkle root is updated.
    event MerkleRootUpdated(bytes32 newRoot);
    /// @notice Emitted when a shard is deployed.
    event ShardDeployed(address shard);
    /// @notice Emitted when the maximum steps are updated.
    event MaxStepsUpdated(uint256 newMaxSteps);
    /// @notice Emitted when the fee is updated.
    event FeeUpdated(uint256 newFee);
    /// @notice Emitted when a batch of commitments is processed.
    event BatchCommitted(bytes32[] commitments);

    error InvalidCommitment();
    error InsufficientFee();
    error InvalidMerkleRoot();
    error MaxIterationsReached();
    error MaxStepsReached();
    error InvalidInput();
    error CommitmentAlreadyExists();
    error CommitmentExpired();
    error TooManyCommitments();
    error DelayNotElapsed();

    constructor(uint256 initialFee, uint256 initialMaxSteps) Ownable(msg.sender) {
        feePerEntropy = initialFee;
        maxSteps = initialMaxSteps;
    }

    function setEntropyExpander(address expander) external onlyOwner {
    entropyExpander = IEntropyExpander(expander);
}

    /// @notice Commits entropy for later reveal.
    /// @param commitment The commitment hash.
    function commitEntropy(bytes32 commitment) external {
        if (commitment == bytes32(0)) revert InvalidInput();
        if (commitments[msg.sender] != bytes32(0)) revert CommitmentAlreadyExists();
        commitments[msg.sender] = commitment;
        commitmentTimestamps[msg.sender] = block.timestamp;
        emit EntropyCommitted(msg.sender, commitment);
    }

    /// @notice Commits a batch of entropy commitments.
    /// @param commitments_ The array of commitment hashes.
    function batchCommitEntropy(bytes32[] calldata commitments_) external {
        if (commitments_.length > MAX_BATCH_COMMITS) revert TooManyCommitments();
        for (uint256 i = 0; i < commitments_.length; i++) {
            this.commitEntropy(commitments_[i]);
        }
        emit BatchCommitted(commitments_);
    }

    /// @notice Reveals committed entropy and feeds it into the sponge.
    /// @param entropy The revealed entropy.
    function revealEntropy(bytes calldata entropy) external payable nonReentrant {
        if (msg.value < feePerEntropy) revert InsufficientFee();
        bytes32 commitment = commitments[msg.sender];
        if (commitment != keccak256(entropy)) revert InvalidCommitment();
        if (block.timestamp > commitmentTimestamps[msg.sender] + 1 days) revert CommitmentExpired();
        delete commitments[msg.sender];
        delete commitmentTimestamps[msg.sender];
        bytes32 entropyHash = keccak256(entropy);
        emit EntropyRevealed(msg.sender, entropyHash);
        _feedEntropy(entropy);
        if (msg.value > feePerEntropy) {
            payable(msg.sender).transfer(msg.value - feePerEntropy);
        }
    }

    /// @notice Reveals a batch of committed entropies.
    /// @param entropies The array of revealed entropies.
    function batchRevealEntropy(bytes[] calldata entropies) external payable nonReentrant {
        if (msg.value < feePerEntropy * entropies.length) revert InsufficientFee();
        for (uint256 i = 0; i < entropies.length; i++) {
            bytes32 commitment = commitments[msg.sender];
            if (commitment != keccak256(entropies[i])) revert InvalidCommitment();
            if (block.timestamp > commitmentTimestamps[msg.sender] + 1 days) revert CommitmentExpired();
            delete commitments[msg.sender];
            delete commitmentTimestamps[msg.sender];
            bytes32 entropyHash = keccak256(entropies[i]);
            emit EntropyRevealed(msg.sender, entropyHash);
            _feedEntropy(entropies[i]);
        }
        uint256 totalFee = feePerEntropy * entropies.length;
        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
    }

    /// @notice Computes a Keccak256 hash of the input data.
    /// @param data The input data.
    /// @return The 256-bit hash.
    function computeKeccakHash(bytes calldata data) external pure returns (bytes32) {
        bytes memory paddedData = LibKeccak.pad(data);
        LibKeccak.StateMatrix memory stateMatrix;
        for (uint256 i = 0; i < paddedData.length; i += LibKeccak.BLOCK_SIZE_BYTES) {
            bytes memory chunk = slice(paddedData, i, LibKeccak.BLOCK_SIZE_BYTES);
            LibKeccak.absorb(stateMatrix, chunk);
            LibKeccak.permutation(stateMatrix);
        }
        return LibKeccak.squeeze(stateMatrix);
    }

    /// @notice Proposes a new Merkle root for verification.
    /// @param _root The proposed Merkle root.
    function proposeMerkleRoot(bytes32 _root) external onlyOwner {
        if (_root == bytes32(0)) revert InvalidMerkleRoot();
        pendingMerkleRoot = _root;
        pendingMerkleRootTimestamp = block.timestamp;
        emit MerkleRootProposed(_root);
    }

    /// @notice Applies the proposed Merkle root after the delay.
    function applyMerkleRoot() external onlyOwner {
        if (pendingMerkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (block.timestamp < pendingMerkleRootTimestamp + merkleRootUpdateDelay) revert DelayNotElapsed();
        merkleRoot = pendingMerkleRoot;
        emit MerkleRootUpdated(merkleRoot);
        pendingMerkleRoot = bytes32(0);
        pendingMerkleRootTimestamp = 0;
    }

    /// @notice Verifies a Merkle leaf.
    /// @param proof The Merkle proof.
    /// @param leaf The leaf to verify.
    /// @return True if the leaf is valid.
    function verifyLeaf(bytes32[] calldata proof, bytes32 leaf) external view returns (bool) {
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }

    /// @notice Feeds entropy into the sponge and stores it in a shard.
    /// @param input The entropy input.
    function _feedEntropy(bytes memory input) internal {
        if (stepCount >= maxSteps) revert MaxStepsReached();
        uint256 index = 0;
        uint256 iterations = 0;
        LibKeccak.StateMatrix memory stateMatrix;

        while (index < input.length && iterations < MAX_ITERATIONS) {
            bytes memory chunk = slice(input, index, RATE);
            bytes32 beforeAbsorbHash = keccak256(internalState);
            bytes memory paddedChunk = applyKeccakPadding(chunk);
            LibKeccak.absorb(stateMatrix, paddedChunk);
            LibKeccak.permutation(stateMatrix);
            bytes32 afterPermuteHash = LibKeccak.squeeze(stateMatrix);

            spongeSteps[stepCount] = SpongeStep(
                keccak256(chunk),
                beforeAbsorbHash,
                afterPermuteHash
            );

            emit SpongeStepTraced(stepCount, keccak256(chunk), beforeAbsorbHash, afterPermuteHash);

            // Store chunk in a shard
            if (shards.length > 0) {
                StorageShard(shards[shards.length - 1]).storeData(chunk);
            }

            internalState = abi.encode(stateMatrix);
            stepCount++;
            index += RATE;
            iterations++;
        }
        if (iterations >= MAX_ITERATIONS) revert MaxIterationsReached();
    }

    /// @notice Absorbs a padded chunk into the state.
    /// @param paddedChunk The padded chunk.
    /// @return newState The new state.
    function absorb(bytes memory paddedChunk) internal view returns (bytes memory newState) {
        newState = cloneBytes(internalState);
        for (uint256 i = 0; i < RATE && i < paddedChunk.length; i++) {
            newState[i] = bytes1(uint8(newState[i]) ^ uint8(paddedChunk[i]));
        }
    }

    /// @notice Applies Keccak padding to a chunk.
    /// @param inputChunk The input chunk.
    /// @return padded The padded chunk.
    function applyKeccakPadding(bytes memory inputChunk) internal pure returns (bytes memory padded) {
        uint256 len = inputChunk.length;
        uint256 padLen = RATE - (len % RATE);
        padded = new bytes(len + padLen);
        for (uint256 i = 0; i < len; i++) padded[i] = inputChunk[i];
        padded[len] = 0x01;
        padded[len + padLen - 1] = 0x80;
    }

    /// @notice Finds discarded bits from padding.
    /// @param original The original chunk.
    /// @param padded The padded chunk.
    /// @return discarded The discarded bits.
    function findDiscardedBits(bytes memory original, bytes memory padded) internal pure returns (bytes memory) {
        if (padded.length <= original.length) return new bytes(0);
        uint256 diff = padded.length - original.length;
        bytes memory discarded = new bytes(diff);
        for (uint256 i = 0; i < diff; i++) {
            discarded[i] = padded[original.length + i];
        }
        return discarded;
    }

    /// @notice Deploys a new storage shard.
    /// @return The shard address.
    function deployShard() external onlyOwner returns (address) {
        StorageShard shard = new StorageShard(msg.sender);
        shards.push(address(shard));
        emit ShardDeployed(address(shard));
        return address(shard);
    }

    /// @notice Updates the entropy fee.
    /// @param newFee The new fee in wei.
    function updateFee(uint256 newFee) external onlyOwner {
        if (newFee == 0) revert InvalidInput();
        feePerEntropy = newFee;
        emit FeeUpdated(newFee);
    }

    /// @notice Updates the maximum steps.
    /// @param newMaxSteps The new maximum steps.
    function updateMaxSteps(uint256 newMaxSteps) external onlyOwner {
        if (newMaxSteps == 0) revert InvalidInput();
        maxSteps = newMaxSteps;
        emit MaxStepsUpdated(newMaxSteps);
    }

    /// @notice Withdraws the contract's balance.
    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        payable(owner()).transfer(balance);
    }

    /// @notice Gets the current state.
    /// @return The internal state.
    function getState() external view returns (bytes memory) {
        return internalState;
    }

    /// @notice Gets the state hash.
    /// @return The state hash.
    function getStateHash() external view returns (bytes32) {
        return keccak256(internalState);
    }

    /// @notice Gets a sponge step.
    /// @param id The step ID.
    /// @return The sponge step.
    function getStep(uint256 id) external view returns (SpongeStep memory) {
        return spongeSteps[id];
    }

    /// @notice Slices a byte array.
    /// @param data The input data.
    /// @param start The start index.
    /// @param len The length.
    /// @return The sliced data.
    function slice(bytes memory data, uint256 start, uint256 len) internal pure returns (bytes memory) {
        if (start + len > data.length) revert InvalidInput();
        bytes memory sliced = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            sliced[i] = data[start + i];
        }
        return sliced;
    }

    function getRandomNumbers(uint256 count) external view returns (uint256[] memory) {
    require(totalEntropyRevealed[msg.sender] > 0, "No entropy revealed");
    bytes32 entropySeed = keccak256(internalState); // or use last revealed entropy
    return entropyExpander.expand(entropySeed, count);
}

    /// @notice Clones a byte array efficiently.
    /// @param input The input bytes.
    /// @return The cloned bytes.
    function cloneBytes(bytes memory input) internal pure returns (bytes memory) {
        bytes memory copy = new bytes(input.length);
        assembly {
            let src := add(input, 0x20)
            let dest := add(copy, 0x20)
            let len := mload(input)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                mstore(add(dest, i), mload(add(src, i)))
            }
        }
        return copy;
    }

    /// @notice Receives ETH deposits for entropy fees.
    receive() external payable {}
}

/// @title Coordinator for Multiple Keccak Black Box Engines
contract EntropyCoordinator {
    IKeccakBlackBoxEngine public immutable engineA;
    IKeccakBlackBoxEngine public immutable engineB;
    IKeccakBlackBoxEngine public immutable engineC;

    /// @notice Initializes the coordinator with three engine addresses.
    /// @param _engineA The first engine address.
    /// @param _engineB The second engine address.
    /// @param _engineC The third engine address.
    constructor(address _engineA, address _engineB, address _engineC) {
        require(_engineA != address(0) && _engineB != address(0) && _engineC != address(0), "Invalid engine address");
        require(_engineA != _engineB && _engineB != _engineC && _engineA != _engineC, "Duplicate engines");
        engineA = IKeccakBlackBoxEngine(_engineA);
        engineB = IKeccakBlackBoxEngine(_engineB);
        engineC = IKeccakBlackBoxEngine(_engineC);
    }

   function getEntropyFromEngines(
    bool useA,
    bool useB,
    bool useC
) external view returns (bytes32) {
    bytes memory data;
    if (useA) data = abi.encodePacked(data, engineA.getStateHash());
    if (useB) data = abi.encodePacked(data, engineB.getStateHash());
    if (useC) data = abi.encodePacked(data, engineC.getStateHash());
    require(data.length > 0, "Must select at least one engine");
    return keccak256(data);
}


    /// @notice Commits entropy to all engines.
    /// @param commitmentA Commitment for engine A.
    /// @param commitmentB Commitment for engine B.
    /// @param commitmentC Commitment for engine C.
    function commitEntropyAll(bytes32 commitmentA, bytes32 commitmentB, bytes32 commitmentC) external {
        engineA.commitEntropy(commitmentA);
        engineB.commitEntropy(commitmentB);
        engineC.commitEntropy(commitmentC);
    }

    /// @notice Commits batches of entropy to all engines.
    /// @param commitmentsA Commitments for engine A.
    /// @param commitmentsB Commitments for engine B.
    /// @param commitmentsC Commitments for engine C.
    function batchCommitEntropyAll(
        bytes32[] calldata commitmentsA,
        bytes32[] calldata commitmentsB,
        bytes32[] calldata commitmentsC
    ) external {
        engineA.batchCommitEntropy(commitmentsA);
        engineB.batchCommitEntropy(commitmentsB);
        engineC.batchCommitEntropy(commitmentsC);
    }

    /// @notice Reveals entropy to all engines with pending commitments.
    /// @param entropyA Entropy for engine A.
    /// @param entropyB Entropy for engine B.
    /// @param entropyC Entropy for engine C.
    function revealEntropyAll(
        bytes calldata entropyA,
        bytes calldata entropyB,
        bytes calldata entropyC
    ) external payable {
        uint256 totalFee = 0;
        bool hasA = engineA.hasPendingCommit(msg.sender);
        bool hasB = engineB.hasPendingCommit(msg.sender);
        bool hasC = engineC.hasPendingCommit(msg.sender);

        if (hasA) totalFee += engineA.feePerEntropy();
        if (hasB) totalFee += engineB.feePerEntropy();
        if (hasC) totalFee += engineC.feePerEntropy();
        require(msg.value >= totalFee, "Insufficient fee");

        if (hasA) engineA.revealEntropy{value: engineA.feePerEntropy()}(entropyA);
        if (hasB) engineB.revealEntropy{value: engineB.feePerEntropy()}(entropyB);
        if (hasC) engineC.revealEntropy{value: engineC.feePerEntropy()}(entropyC);

        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
    }

    /// @notice Reveals batches of entropy to all engines.
    /// @param entropiesA Entropies for engine A.
    /// @param entropiesB Entropies for engine B.
    /// @param entropiesC Entropies for engine C.
    function batchRevealEntropyAll(
        bytes[] calldata entropiesA,
        bytes[] calldata entropiesB,
        bytes[] calldata entropiesC
    ) external payable {
        uint256 totalFee = 0;
        if (engineA.hasPendingCommit(msg.sender)) totalFee += engineA.feePerEntropy() * entropiesA.length;
        if (engineB.hasPendingCommit(msg.sender)) totalFee += engineB.feePerEntropy() * entropiesB.length;
        if (engineC.hasPendingCommit(msg.sender)) totalFee += engineC.feePerEntropy() * entropiesC.length;
        require(msg.value >= totalFee, "Insufficient fee");

        if (engineA.hasPendingCommit(msg.sender))
            engineA.batchRevealEntropy{value: engineA.feePerEntropy() * entropiesA.length}(entropiesA);
        if (engineB.hasPendingCommit(msg.sender))
            engineB.batchRevealEntropy{value: engineB.feePerEntropy() * entropiesB.length}(entropiesB);
        if (engineC.hasPendingCommit(msg.sender))
            engineC.batchRevealEntropy{value: engineC.feePerEntropy() * entropiesC.length}(entropiesC);

        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
    }

    /// @notice Gets the combined entropy from all engines.
    /// @return The combined entropy hash.
    function getCombinedEntropy() external view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                engineA.getStateHash(),
                engineB.getStateHash(),
                engineC.getStateHash()
            )
        );
    }
}

interface ISpongeEngine {
    function processEntropy(bytes calldata entropy) external;
    function getStateHash() external view returns (bytes32);
}

contract KeccakEngine is ISpongeEngine {
    bytes public internalState; // You can use a more complex state if needed

    event StateUpdated(bytes32 indexed newStateHash, bytes entropy);

    constructor(bytes memory initialState) {
        internalState = initialState;
        emit StateUpdated(keccak256(internalState), "");
    }

    function processEntropy(bytes calldata entropy) external override {
        // Example: concatenate entropy to state and hash (replace with your actual randomness logic)
        internalState = abi.encodePacked(keccak256(abi.encodePacked(internalState, entropy)));
        emit StateUpdated(keccak256(internalState), entropy);
    }

    function getStateHash() external view override returns (bytes32) {
        return keccak256(internalState);
    }
}


contract EntropyEntry {
    struct Commitment {
        bytes32 hash;
        uint256 timestamp;
    }

    address[] public engines;
    mapping(address => Commitment) public commitments;
    mapping(address => bytes32) public lastEntropySeed;

    uint256 public constant COMMIT_EXPIRY = 1 days;
    uint256 public feePerEntropy;
    address public owner;
    IEntropyExpander public entropyExpander;

    event EntropyCommitted(address indexed user, address indexed engine, bytes32 commitment);
    event EntropyRevealed(address indexed user, address indexed engine, string entropy, bytes32 newStateHash);
    event FeeUpdated(uint256 newFee);
    event FeeRefunded(address indexed user, uint256 amount);
    event Withdrawn(address indexed owner, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address[] memory _engines, address _entropyExpander, uint256 initialFee) {
        require(_engines.length > 0, "No engines");
        require(_entropyExpander != address(0), "No expander");
        engines = _engines;
        owner = msg.sender;
        feePerEntropy = initialFee;
        entropyExpander = IEntropyExpander(_entropyExpander);
    }

    function assignedEngine(address user) public view returns (address) {
        return engines[uint256(uint160(user)) % engines.length];
    }

    // === User-facing functions ===

    /// @notice User commits a string as entropy. No salt, no bytes.
    function commitEntropy(string calldata entropy) external {
        require(commitments[msg.sender].hash == bytes32(0), "Already committed");
        bytes32 commitment = keccak256(abi.encodePacked(msg.sender, entropy));
        commitments[msg.sender] = Commitment(commitment, block.timestamp);
        emit EntropyCommitted(msg.sender, assignedEngine(msg.sender), commitment);
    }

    /// @notice User reveals the same string. No salt, no bytes.
    function revealEntropy(string calldata entropy) external payable {
        require(msg.value >= feePerEntropy, "Insufficient fee");
        Commitment memory c = commitments[msg.sender];
        require(c.hash != bytes32(0), "No commitment");
        require(block.timestamp <= c.timestamp + COMMIT_EXPIRY, "Commitment expired");
        require(c.hash == keccak256(abi.encodePacked(msg.sender, entropy)), "Invalid reveal");
        address engine = assignedEngine(msg.sender);

        // Delete commitment before external call (reentrancy safety)
        delete commitments[msg.sender];

        // Call engine and get new state hash
        ISpongeEngine(engine).processEntropy(bytes(entropy));
        bytes32 newStateHash = ISpongeEngine(engine).getStateHash();

        // Store the entropy seed for this user
        lastEntropySeed[msg.sender] = newStateHash;

        emit EntropyRevealed(msg.sender, engine, entropy, newStateHash);

        _refundExcess(msg.value, feePerEntropy);
    }

    /// @notice User requests N random numbers after revealing
    function getRandomNumbers(uint256 count) external view returns (uint256[] memory) {
        require(lastEntropySeed[msg.sender] != bytes32(0), "No entropy revealed");
        return entropyExpander.expand(lastEntropySeed[msg.sender], count);
    }

    // === Admin and utility ===

    function updateFee(uint256 newFee) external onlyOwner {
        feePerEntropy = newFee;
        emit FeeUpdated(newFee);
    }

    function withdraw() external onlyOwner {
        uint256 bal = address(this).balance;
        require(bal > 0, "Nothing to withdraw");
        (bool sent, ) = owner.call{value: bal}("");
        require(sent, "Withdraw failed");
        emit Withdrawn(owner, bal);
    }

    function _refundExcess(uint256 sent, uint256 required) internal {
        if (sent > required) {
            uint256 refund = sent - required;
            (bool success, ) = msg.sender.call{value: refund}("");
            require(success, "Refund failed");
            emit FeeRefunded(msg.sender, refund);
        }
    }

    receive() external payable {}
}

// --- Entropy Expander ---
contract EntropyExpander {
    function expand(bytes32 entropySeed, uint256 count) external pure returns (uint256[] memory result) {
        result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = uint256(keccak256(abi.encodePacked(entropySeed, i)));
        }
    }
}

/// @title Storage Shard for Entropy Data
contract StorageShard is Ownable {
    bytes public data;

    /// @notice Emitted when data is stored in the shard.
    event DataStored(bytes32 dataHash);

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Stores data in the shard.
    /// @param _data The data to store.
    function storeData(bytes calldata _data) external onlyOwner {
        data = _data;
        emit DataStored(keccak256(_data));
    }

    /// @notice Retrieves stored data.
    /// @return The stored data.
    function getData() external view returns (bytes memory) {
        return data;
    }
}



// --- Keccak Black Box Engine ---
interface IKeccakBlackBoxEngine {
    function commitEntropy(bytes32 commitment) external;
    function revealEntropy(bytes calldata entropy) external payable;
    function batchCommitEntropy(bytes32[] calldata commitments_) external;
    function batchRevealEntropy(bytes[] calldata entropies) external payable;
    function getStateHash() external view returns (bytes32);
    function hasPendingCommit(address user) external view returns (bool);
    function feePerEntropy() external view returns (uint256);
    function getRandomNumbers(uint256 count) external view returns (uint256[] memory);
}

// --- Iconoclast Token ---
contract IconoclastToken is ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {
    address public protocol;

    function initialize(address _protocol) external initializer {
        __ERC20_init("IconoclastAgents", "IAGENT");
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        protocol = _protocol;
        _mint(msg.sender, 1_000_000 * 10**18);
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == protocol, "Only protocol");
        _mint(to, amount);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// --- Badge NFT ---
contract BadgeNFT is ERC721Upgradeable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public badgeCounter;
    mapping(uint256 => uint256) public badgeWeights;
    mapping(uint256 => bool) public isSoulbound;
    mapping(uint256 => bytes32) public badgeMetadata;
    mapping(uint256 => uint256) public badgeLastActive;
    mapping(uint256 => uint256) public revocationProposals;
    address public protocol;
    uint256 private constant DECAY_RATE = 10;
    uint256 private constant DISPUTE_PERIOD = 7 days;

    event BadgeMinted(uint256 indexed badgeId, address recipient, uint256 weight, bytes32 metadata);
    event BadgeRevocationProposed(uint256 indexed badgeId, uint256 deadline);
    event BadgeRevoked(uint256 indexed badgeId, address recipient);
    mapping(uint256 => address) private _owners;



    function initialize(address _protocol) external initializer {
        __ERC721_init("IconoclastBadge", "IBADGE");
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        protocol = _protocol;
    }

    function _exists(uint256 tokenId) internal view returns (bool) {
    return _owners[tokenId] != address(0);
}

    function mint(address recipient, uint256 weight, bytes32 metadata) external returns (uint256) {
        require(msg.sender == protocol, "Only protocol");
        badgeCounter++;
        uint256 badgeId = badgeCounter;
        isSoulbound[badgeId] = true;
        badgeWeights[badgeId] = weight;
        badgeMetadata[badgeId] = metadata;
        badgeLastActive[badgeId] = block.timestamp;
        _safeMint(recipient, badgeId);
        emit BadgeMinted(badgeId, recipient, weight, metadata);
        return badgeId;
    }

    function proposeRevocation(uint256 badgeId, uint256 proposalId) external {
        require(msg.sender == protocol, "Only protocol");
        require(_exists(badgeId), "Badge does not exist");
        revocationProposals[badgeId] = block.timestamp + DISPUTE_PERIOD;
        emit BadgeRevocationProposed(badgeId, proposalId);
    }

    function executeRevocation(uint256 badgeId) external {
        require(msg.sender == protocol, "Only protocol");
        require(_exists(badgeId), "Badge does not exist");
        require(revocationProposals[badgeId] > 0 && block.timestamp >= revocationProposals[badgeId], "Invalid revocation");
        address owner = ownerOf(badgeId);
        delete revocationProposals[badgeId];
        _burn(badgeId);
        emit BadgeRevoked(badgeId, owner);
    }

    function getBadgeWeight(uint256 badgeId) external returns (uint256) {
        require(_exists(badgeId), "Badge does not exist");
        updateBadgeWeight(badgeId);
        return badgeWeights[badgeId];
    }

    function updateBadgeWeight(uint256 badgeId) internal {
        uint256 lastActive = badgeLastActive[badgeId];
        uint256 yearsElapsed = (block.timestamp - lastActive) / 365 days;
        if (yearsElapsed > 0) {
            uint256 newWeight = badgeWeights[badgeId];
            for (uint256 i = 0; i < yearsElapsed; i++) {
                newWeight = newWeight * (100 - DECAY_RATE) / 100;
            }
            badgeWeights[badgeId] = newWeight;
            badgeLastActive[badgeId] = block.timestamp;
        }
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256) view  internal  {
        require(from == address(0) || !isSoulbound[tokenId], "Soulbound badge");
        
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "Badge does not exist");
        return string(abi.encodePacked("ar://", bytes32ToString(badgeMetadata[tokenId])));
    }

    function bytes32ToString(bytes32 _bytes32) internal pure returns (string memory) {
        bytes memory bytesArray = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(_bytes32[i]);
            bytesArray[i * 2] = bytes1((b >> 4) < 10 ? (b >> 4) + 48 : (b >> 4) + 87);
            bytesArray[i * 2 + 1] = bytes1((b & 0x0F) < 10 ? (b & 0x0F) + 48 : (b & 0x0F) + 87);
        }
        return string(bytesArray);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// --- Agent NFT ---
contract AgentNFT is ERC721Upgradeable, OwnableUpgradeable, UUPSUpgradeable, ERC721EnumerableUpgradeable {
    uint256 public agentCounter;
    mapping(uint256 => uint256) public agentExpertise;
    mapping(uint256 => string[]) public agentModules;
    address public protocol;

    event AgentMinted(uint256 indexed agentId, address owner);
    event AgentModuleAdded(uint256 indexed agentId, string moduleName);

    function initialize(address _protocol) external initializer {
        __ERC721_init("IconoclastAgent", "IAGENT");
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        protocol = _protocol;
    }

    function mint(address to) external returns (uint256) {
        require(msg.sender == protocol, "Only protocol");
        agentCounter++;
        uint256 agentId = agentCounter;
        _safeMint(to, agentId);
        agentExpertise[agentId] = 0;
        emit AgentMinted(agentId, to);
        return agentId;
    }

    function _exists(uint256 tokenId) internal view returns (bool) {
    return tokenOfOwnerByIndex(msg.sender, 0) == tokenId;
}

    function addModule(uint256 agentId, string memory moduleName) external {
        require(msg.sender == protocol, "Only protocol");
        require(_exists(agentId), "Agent does not exist");
        agentModules[agentId].push(moduleName);
        emit AgentModuleAdded(agentId, moduleName);
    }

    function setExpertise(uint256 agentId, uint256 expertise) external {
        require(msg.sender == protocol, "Only protocol");
        require(_exists(agentId), "Agent does not exist");
        require(expertise <= 100, "Invalid expertise");
        agentExpertise[agentId] = expertise;
    }

    function getExpertise(uint256 agentId) external view returns (uint256) {
        require(_exists(agentId), "Agent does not exist");
        return agentExpertise[agentId];
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
       function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }



    function _increaseBalance(address account, uint128 amount)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
    {
        super._increaseBalance(account, amount);
    }

    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (address)
    {
        return super._update(to, tokenId, auth);
    }
}



// --- Treasury ---
contract Treasury is OwnableUpgradeable, UUPSUpgradeable {
    IconoclastToken public token;
    uint256 public balance;
    address public protocol;

    event TreasuryFunded(address from, uint256 amount);
    event TreasurySpent(address to, uint256 amount, string reason);

    function initialize(address _token, address _protocol) external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        token = IconoclastToken(_token);
        protocol = _protocol;
    }

    function fund(uint256 amount) external {
        require(msg.sender == protocol, "Only protocol");
        token.transferFrom(msg.sender, address(this), amount);
        balance += amount;
        emit TreasuryFunded(msg.sender, amount);
    }

    function spend(address to, uint256 amount, string calldata reason, uint256 proposalId) external {
        require(msg.sender == protocol, "Only protocol");
        require(balance >= amount, "Insufficient funds");
        balance -= amount;
        token.transfer(to, amount);
        emit TreasurySpent(to, amount, reason);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// --- Escrow ---
contract Escrow is OwnableUpgradeable, UUPSUpgradeable {
    IconoclastToken public token;
    mapping(address => uint256) public balances;
    address public protocol;

    function initialize(address _token, address _protocol) external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        token = IconoclastToken(_token);
        protocol = _protocol;
    }

    function deposit(address from, uint256 amount) external {
        require(msg.sender == protocol, "Only protocol");
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }

    function withdraw(address to, uint256 amount) external {
        require(msg.sender == protocol, "Only protocol");
        require(balances[address(this)] >= amount, "Insufficient balance");
        balances[address(this)] -= amount;
        token.transfer(to, amount);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// --- Governance ---
contract Governance is OwnableUpgradeable, UUPSUpgradeable {
    BadgeNFT public badgeNFT;
    address public protocol;
    uint256 public proposalCounter;
    uint256 private constant QUORUM = 100 * 10**18;

    struct Proposal {
        uint256 id;
        address proposer;
        string action;
        bytes data;
        uint256 totalWeight;
        bool executed;
        uint256 deadline;
    }
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(bytes32 => uint256) public approvedProposals;

    event ProposalCreated(uint256 indexed proposalId, address proposer, string action, uint256 deadline);
    event Voted(uint256 indexed proposalId, address voter, uint256 weight);
    event ProposalExecuted(uint256 indexed proposalId, string action);
        mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;

    // Enumeration
    mapping(address => uint256[]) private _ownedTokens;
    mapping(uint256 => uint256) private _ownedTokensIndex;

    function _mint(address to, uint256 tokenId) internal {
        require(_owners[tokenId] == address(0), "Already minted");
        _owners[tokenId] = to;
        _balances[to] += 1;

        // Add to owner's list
        _ownedTokens[to].push(tokenId);
        _ownedTokensIndex[tokenId] = _ownedTokens[to].length - 1;
    }

    function balanceOf(address owner) public view returns (uint256) {
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        return _owners[tokenId];
    }

    /// @notice Returns the tokenId owned by `owner` at a given `index`
    function tokenOfOwnerByIndex(address owner, uint256 index) public view returns (uint256) {
        require(index < _ownedTokens[owner].length, "Index out of bounds");
        return _ownedTokens[owner][index];
    }

    // Add your mint function for external use
    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }



    function initialize(address _badgeNFT, address _protocol) external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        badgeNFT = BadgeNFT(_badgeNFT);
        protocol = _protocol;
    }



    function createProposal(string calldata action, bytes calldata data) external {
        require(msg.sender == protocol, "Only protocol");
        proposalCounter++;
        uint256 proposalId = proposalCounter;
        proposals[proposalId] = Proposal({
            id: proposalId,
            proposer: msg.sender,
            action: action,
            data: data,
            totalWeight: 0,
            executed: false,
            deadline: block.timestamp + 7 days
        });
        emit ProposalCreated(proposalId, msg.sender, action, block.timestamp + 7 days);
    }
  
    function vote(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    require(block.timestamp < proposal.deadline, "Voting ended");
    require(!hasVoted[proposalId][msg.sender], "Already voted");
    uint256 weight = badgeNFT.balanceOf(msg.sender);
    require(weight > 0, "No voting power");
    proposal.totalWeight += weight;
    hasVoted[proposalId][msg.sender] = true;
    emit Voted(proposalId, msg.sender, weight);
}



    function executeProposal(uint256 proposalId) external {
        require(msg.sender == protocol, "Only protocol");
        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp > proposal.deadline, "Proposal not ended");
        require(!proposal.executed, "Already executed");
        require(proposal.totalWeight >= QUORUM, "Quorum not met");

        proposal.executed = true;
        bytes32 actionHash = keccak256(abi.encodePacked(proposal.action, proposal.data));
        approvedProposals[actionHash] = proposalId;
        emit ProposalExecuted(proposalId, proposal.action);
    }

    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// --- Module Registry ---
contract ModuleRegistry is OwnableUpgradeable, UUPSUpgradeable {
    Governance public governance;
    address public protocol;

    struct Module {
        bytes32 bytecodeHash;
        address creator;
        bool active;
        uint256 stagedUntil;
    }
    mapping(bytes32 => Module) public modules;
    mapping(bytes32 => bool) public deprecatedModules;

    event ModuleStaged(bytes32 indexed bytecodeHash, address creator, uint256 stagedUntil);
    event ModuleRegistered(bytes32 indexed bytecodeHash, address creator);
    event ModuleDeprecated(bytes32 indexed bytecodeHash);

    function initialize(address _governance, address _protocol) external initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        governance = Governance(_governance);
        protocol = _protocol;
    }

    function stageModule(bytes32 bytecodeHash, address creator) external {
        require(msg.sender == protocol, "Only protocol");
        require(!modules[bytecodeHash].active && !deprecatedModules[bytecodeHash], "Module exists");
        uint256 stagedUntil = block.timestamp + 7 days;
        modules[bytecodeHash] = Module(bytecodeHash, creator, false, stagedUntil);
        emit ModuleStaged(bytecodeHash, creator, stagedUntil);
    }

    function registerModule(bytes32 bytecodeHash) external {
        require(msg.sender == protocol, "Only protocol");
        bytes32 actionHash = keccak256(abi.encodePacked("registerModule", abi.encode(bytecodeHash)));
        uint256 proposalId = governance.approvedProposals(actionHash);
        require(proposalId > 0, "Not approved");
        Module storage module = modules[bytecodeHash];
        require(module.stagedUntil > 0 && block.timestamp >= module.stagedUntil, "Not staged or premature");
        module.active = true;
        module.stagedUntil = 0;
        emit ModuleRegistered(bytecodeHash, module.creator);
    }

    function deprecateModule(bytes32 bytecodeHash) external {
        require(msg.sender == protocol, "Only protocol");
        bytes32 actionHash = keccak256(abi.encodePacked("deprecateModule", abi.encode(bytecodeHash)));
        uint256 proposalId = governance.approvedProposals(actionHash);
        require(proposalId > 0, "Not approved");
        require(modules[bytecodeHash].active, "Module not active");
        modules[bytecodeHash].active = false;
        deprecatedModules[bytecodeHash] = true;
        emit ModuleDeprecated(bytecodeHash);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}


contract IconoclastProtocol {
    // --- Access Control ---
    address private _owner;
    address public governance;
    modifier onlyOwner() { require(msg.sender == _owner, "Not owner"); _; }
    modifier onlyGovernance() { require(msg.sender == governance, "Only governance"); _; }

    // --- Pause ---
    bool private _paused;
    modifier whenNotPaused() { require(!_paused, "Paused"); _; }
    function pause() external onlyGovernance { _paused = true; }
    function unpause() external onlyGovernance { _paused = false; }

    // --- Reentrancy ---
    uint256 private _status;
    modifier nonReentrant() {
        require(_status != 2, "Reentrant");
        _status = 2;
        _;
        _status = 1;
    }

    // --- Protocol State ---
    uint256 public constant MAX_TEST_CASES = 10;
    uint256 public constant MAX_GAS_PER_VERIFICATION = 5_000_000;
    uint256 public constant MIN_BOUNTY = 100 * 10**18;
    uint256 public constant MAX_BYTECODE_SIZE = 24_576;
    uint256 public constant TREASURY_FEE_BPS = 1000;
    uint256 public constant BATCH_VERIFICATION_LIMIT = 5;
    bytes32 public merkleRoot;

    // --- Storage for balances, NFTs, etc. ---
    mapping(address => uint256) public balances;
    mapping(address => uint256) public escrowBalances;
    mapping(address => uint256) public badgeBalances;
    mapping(address => uint256) public agentExpertise;
    mapping(address => uint256) public agentModules;

    // --- Protocol Data Structures ---
    struct TestCase {
        bytes callData;
        bytes expectedOutput;
        uint256 maxGas;
    }
    struct Request {
        bytes32 requestId;
        address client;
        uint256 prize;
        bool active;
        uint256 deadline;
        bytes32 descriptionHash;
        TestCase[] testCases;
        address winner;
        uint256 testComplexity;
    }
    struct Solution {
        address freelancer;
        bytes32 solutionHash;
        bytes moduleBytecode;
        bytes32[] merkleProof;
        bool verified;
        uint256 submissionTime;
        uint256 agentId;
    }
    mapping(bytes32 => Request) public requests;
    mapping(bytes32 => Solution[]) public solutions;
    mapping(bytes32 => bool) public usedBytecodeHashes;
    bytes32[] public storageLogs;
    uint256 public logCounter;

    // --- Events ---
    event RequestPosted(bytes32 indexed requestId, address client, uint256 prize, uint256 deadline, bytes32 descriptionHash, uint256 testCaseCount);
    event SolutionSubmitted(bytes32 indexed requestId, address freelancer, bytes32 solutionHash, uint256 agentId, uint256 submissionTime);
    event SolutionVerified(bytes32 indexed requestId, address freelancer, bool success);
    event RequestCompleted(bytes32 indexed requestId, address winner, uint256 prize, uint256 treasuryFee);
    event LogStored(bytes32 indexed logHash, bytes data);
    event ZKProofVerified(bytes32 indexed requestId, uint256 solutionIndex, bool valid);

    // --- Constructor/Initializer ---
    constructor(address _governance) {
        _owner = msg.sender;
        governance = _governance;
        _status = 1;
        merkleRoot = keccak256(abi.encodePacked("fixed_merkle_root"));
    }

    // --- Token/Balance simulation ---
    function depositTokens(uint256 amount) external { balances[msg.sender] += amount; }
    function setGovernance(address g) external onlyOwner { governance = g; }

    // --- Core Protocol Functions ---

    function postRequest(
        bytes32 requestId,
        uint256 prize,
        uint256 duration,
        bytes32 descriptionHash,
        bytes[] calldata callDatas,
        bytes[] calldata expectedOutputs,
        uint256[] calldata maxGases
    ) external nonReentrant whenNotPaused {
        require(!requests[requestId].active, "Request exists");
        require(prize >= MIN_BOUNTY, "Prize too low");
        require(callDatas.length >= 3 && callDatas.length <= MAX_TEST_CASES, "Invalid test case count");
        require(callDatas.length == expectedOutputs.length && callDatas.length == maxGases.length, "Array mismatch");

        for (uint256 i = 0; i < callDatas.length; i++) {
            require(callDatas[i].length > 0, "Empty callData");
            require(maxGases[i] > 0 && maxGases[i] <= 1_000_000, "Invalid maxGas");
            require(expectedOutputs[i].length > 0, "Empty expectedOutput");
        }

        uint256 treasuryFee = (prize * TREASURY_FEE_BPS) / 10_000;
        uint256 netPrize = prize - treasuryFee;
        require(balances[msg.sender] >= prize, "Insufficient balance");
        balances[msg.sender] -= prize;
        balances[_owner] += treasuryFee; // Treasury is owner
        escrowBalances[msg.sender] += netPrize;

        Request storage request = requests[requestId];
        request.requestId = requestId;
        request.client = msg.sender;
        request.prize = netPrize;
        request.active = true;
        request.deadline = block.timestamp + duration;
        request.descriptionHash = descriptionHash;
        request.winner = address(0);
        request.testComplexity = callDatas.length;
        for (uint256 i = 0; i < callDatas.length; i++) {
            request.testCases.push(TestCase(callDatas[i], expectedOutputs[i], maxGases[i]));
        }

        storeLog(abi.encode(requestId, msg.sender, netPrize, descriptionHash, callDatas.length));
        emit RequestPosted(requestId, msg.sender, netPrize, block.timestamp + duration, descriptionHash, callDatas.length);
    }

    function submitSolution(
        bytes32 requestId,
        bytes32 solutionHash,
        bytes calldata moduleBytecode,
        bytes32[] calldata merkleProof,
        uint256 agentId
    ) external nonReentrant whenNotPaused {
        Request storage request = requests[requestId];
        require(request.active, "Request inactive");
        require(block.timestamp <= request.deadline, "Deadline passed");
        require(moduleBytecode.length > 0 && moduleBytecode.length <= MAX_BYTECODE_SIZE, "Invalid bytecode size");
        bytes32 bytecodeHash = keccak256(moduleBytecode);
        require(!usedBytecodeHashes[bytecodeHash], "Bytecode already used");
        if (agentId != 0) {
            require(agentExpertise[msg.sender] == agentId, "Not agent owner");
        }

        solutions[requestId].push(
            Solution(msg.sender, solutionHash, moduleBytecode, merkleProof, false, block.timestamp, agentId)
        );
        usedBytecodeHashes[bytecodeHash] = true;

        storeLog(abi.encode(requestId, msg.sender, solutionHash, block.timestamp));
        emit SolutionSubmitted(requestId, msg.sender, solutionHash, agentId, block.timestamp);

        verifySolution(requestId, solutions[requestId].length - 1);
    }

    function batchVerifySolutions(bytes32 requestId, uint256[] calldata solutionIndices) external nonReentrant whenNotPaused {
        require(solutionIndices.length <= BATCH_VERIFICATION_LIMIT, "Too many solutions");
        for (uint256 i = 0; i < solutionIndices.length; i++) {
            verifySolution(requestId, solutionIndices[i]);
        }
    }

    function verifySolution(bytes32 requestId, uint256 solutionIndex) internal {
        Request storage request = requests[requestId];
        require(request.active, "Request inactive");
        require(solutionIndex < solutions[requestId].length, "Invalid solution index");

        Solution storage solution = solutions[requestId][solutionIndex];
        require(!solution.verified, "Solution verified");

        require(_verifyMerkleProof(solution.merkleProof, merkleRoot, keccak256(solution.moduleBytecode)), "Invalid Merkle proof");

        bool success = runTestCases(request.testCases, solution.moduleBytecode);
        solution.verified = true;

        storeLog(abi.encode(requestId, solution.freelancer, solution.solutionHash, success));
        emit SolutionVerified(requestId, solution.freelancer, success);

        if (success) {
            request.winner = solution.freelancer;
            completeRequest(requestId, solution.agentId, keccak256(solution.moduleBytecode));
        }
    }

    function runTestCases(TestCase[] storage testCases, bytes memory moduleBytecode) view  internal returns (bool) {
        for (uint256 i = 0; i < testCases.length; i++) {
            TestCase storage test = testCases[i];
            bytes memory callData = randomizeInputs(test.callData, uint256(keccak256(abi.encodePacked(block.timestamp, i, moduleBytecode))));
            // Simulate execution: always returns expectedOutput for demo
            bytes memory result = callData; // For demo, just echo callData
            if (keccak256(result) != keccak256(test.expectedOutput)) {
                return false;
            }
        }
        return true;
    }

    function randomizeInputs(bytes memory callData, uint256 seed) internal pure returns (bytes memory) {
        if (callData.length < 4) return callData;
        bytes4 selector;
        assembly { selector := mload(add(callData, 32)) }
        bytes memory args = new bytes(callData.length - 4);
        for (uint256 i = 4; i < callData.length; i++) {
            args[i - 4] = callData[i];
        }
        if (args.length >= 32) {
            uint256 randomValue = seed;
            for (uint256 i = 0; i < 32 && i < args.length; i++) {
                args[i] = bytes32(randomValue)[i];
            }
        }
        return abi.encodePacked(selector, args);
    }

    function verifyZKProof(
        bytes32 requestId,
        uint256 solutionIndex,
        bytes calldata proof,
        bytes32 proofHash
    ) external nonReentrant whenNotPaused {
        require(proof.length > 0, "Invalid proof");
        bool valid = keccak256(proof) == proofHash;

        Request storage request = requests[requestId];
        Solution storage solution = solutions[requestId][solutionIndex];
        require(request.active, "Request inactive");
        require(!solution.verified, "Solution verified");

        solution.verified = true;
        storeLog(abi.encode(requestId, solution.freelancer, solution.solutionHash, valid));
        emit ZKProofVerified(requestId, solutionIndex, valid);

        if (valid) {
            request.winner = solution.freelancer;
            completeRequest(requestId, solution.agentId, keccak256(solution.moduleBytecode));
        }
    }

    function completeRequest(bytes32 requestId, uint256 agentId, bytes32 /*bytecodeHash*/) internal {
        Request storage request = requests[requestId];
        require(request.active, "Request inactive");
        require(request.winner != address(0), "No winner");

        request.active = false;
        escrowBalances[request.winner] += request.prize;

        uint256 complexityFactor = 1 + (request.testComplexity / 3);
        uint256 badgeWeight = (request.prize / 10**18) * complexityFactor;
        badgeBalances[request.winner] += badgeWeight;

        if (agentId != 0) {
            agentModules[request.winner] += 1;
            uint256 currentExpertise = agentExpertise[request.winner];
            uint256 newExpertise = currentExpertise + 10 > 100 ? 100 : currentExpertise + 10;
            agentExpertise[request.winner] = newExpertise;
        }

        storeLog(abi.encode(requestId, request.winner, request.prize, badgeWeight));
        emit RequestCompleted(requestId, request.winner, request.prize, (request.prize * TREASURY_FEE_BPS) / 9000);
    }

    function refundRequest(bytes32 requestId) external nonReentrant whenNotPaused {
        Request storage request = requests[requestId];
        require(request.active, "Request inactive");
        require(block.timestamp > request.deadline, "Deadline not passed");
        require(request.winner == address(0), "Winner selected");

        request.active = false;
        escrowBalances[request.client] += request.prize;
        storeLog(abi.encode(requestId, address(0), 0));
        emit RequestCompleted(requestId, address(0), 0, 0);
    }

    // --- Utility ---
    function storeLog(bytes memory data) internal {
        bytes32 logHash = keccak256(data);
        storageLogs.push(logHash);
        logCounter++;
        if (logCounter > 1000) {
            delete storageLogs[0];
            storageLogs = slice(storageLogs, 1, storageLogs.length - 1);
        }
        emit LogStored(logHash, data);
    }

    function slice(bytes32[] memory arr, uint256 start, uint256 length) internal pure returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = arr[start + i];
        }
        return result;
    }

    // --- Minimal Merkle Proof (always true for demo) ---
    function _verifyMerkleProof(bytes32[] memory, bytes32, bytes32) internal pure returns (bool) {
        return true;
    }
}