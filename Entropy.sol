// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IKeccakBlackBoxEngine {
    function commitEntropy(bytes32 commitment) external;
    function revealEntropy(bytes calldata entropy) external payable;
    function batchCommitEntropy(bytes32[] calldata commitments_) external;
    function batchRevealEntropy(bytes[] calldata entropies) external payable;
    function getStateHash() external view returns (bytes32);
    function hasPendingCommit(address user) external view returns (bool);
    function feePerEntropy() external view returns (uint256);
    function batchCommitEntropyForUsers(address[] calldata users, bytes32[] calldata commitments_) external;
    function batchRevealEntropyForUsers(address[] calldata users, bytes[] calldata entropies) external payable;

}

library LibKeccak {
    uint256 internal constant BLOCK_SIZE_BYTES = 136;
    bytes internal constant ROUND_CONSTANTS = abi.encode(
        0x00000000000000010000000000008082800000000000808a8000000080008000,
        0x000000000000808b000000008000000180000000800080818000000000008009,
        0x000000000000008a00000000000000880000000080008009000000008000000a,
        0x000000008000808b800000000000008b80000000000080898000000000008003,
        0x80000000000080028000000000000080000000000000800a800000008000000a,
        0x8000000080008081800000000000808000000000800000018000000080008008
    );
    uint64 private constant U64_MASK = 0xFFFFFFFFFFFFFFFF;

    struct StateMatrix {
        uint64[25] state;
    }

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

    error InvalidInput();
}

contract StorageShard is Ownable {
    bytes public data;

    event DataStored(bytes32 dataHash);

    constructor(address initialOwner) Ownable(initialOwner) {}

    function storeData(bytes calldata _data) external onlyOwner {
        data = _data;
        emit DataStored(keccak256(_data));
    }

    function getData() external view returns (bytes memory) {
        return data;
    }
}

contract KeccakBlackBoxEngine is Ownable, ReentrancyGuard, IKeccakBlackBoxEngine {
    using LibKeccak for LibKeccak.StateMatrix;

    uint256 public constant STATE_SIZE = 200;
    uint256 public constant RATE = 136;
    uint256 public constant CAPACITY = 64;
    uint256 public constant MAX_ITERATIONS = 100;
    uint256 public constant MAX_BATCH_COMMITS = 50;

    uint256 public feePerEntropy = 0.001 ether;
    uint256 public stepCount;
    uint256 public maxSteps = 1000;
    uint256 public merkleRootUpdateDelay = 1 days;
    uint256 public pendingMerkleRootTimestamp;

    bytes public internalState = new bytes(STATE_SIZE);
    bytes32 public merkleRoot;
    bytes32 public pendingMerkleRoot;
    address[] public shards;

    mapping(uint256 => SpongeStep) public spongeSteps;
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitmentTimestamps;
    mapping(address => bool) public authorizedCommitters;

    struct SpongeStep {
        bytes32 inputChunkHash;
        bytes32 beforeAbsorbHash;
        bytes32 afterPermuteHash;
    }

    event SpongeStepTraced(
        uint256 indexed stepId,
        bytes32 inputChunkHash,
        bytes32 beforeAbsorbHash,
        bytes32 afterPermuteHash
    );
    event EntropyCommitted(address indexed contributor, bytes32 commitment);
    event EntropyRevealed(address indexed contributor, bytes32 entropyHash);
    event MerkleRootProposed(bytes32 newRoot);
    event MerkleRootUpdated(bytes32 newRoot);
    event ShardDeployed(address shard);
    event MaxStepsUpdated(uint256 newMaxSteps);
    event FeeUpdated(uint256 newFee);
    event BatchCommitted(bytes32[] commitments);
    event CommitterAdded(address committer);
    event CommitterRemoved(address committer);

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
    error UnauthorizedCommitter();

    constructor(uint256 initialFee, uint256 initialMaxSteps) Ownable(msg.sender) {
        feePerEntropy = initialFee;
        maxSteps = initialMaxSteps;
    }


    function addCommitter(address committer) external onlyOwner {
        require(committer != address(0), "Invalid committer address");
        require(!authorizedCommitters[committer], "Committer already added");
        authorizedCommitters[committer] = true;
        emit CommitterAdded(committer);
    }

    function removeCommitter(address committer) external onlyOwner {
        require(committer != address(0), "Invalid committer address");
        require(authorizedCommitters[committer], "Committer not found");
        authorizedCommitters[committer] = false;
        emit CommitterRemoved(committer);
    }

    // Pluggable: batch commit for multiple users (onlyOwner or authorized)
function batchCommitEntropyForUsers(address[] calldata users, bytes32[] calldata commitments_) external onlyOwner {
    require(users.length == commitments_.length, "Mismatched array lengths");
    for (uint i = 0; i < users.length; i++) {
        // Use internal logic, but for each user
        if (commitments[users[i]] != bytes32(0)) revert CommitmentAlreadyExists();
        commitments[users[i]] = commitments_[i];
        commitmentTimestamps[users[i]] = block.timestamp;
        emit EntropyCommitted(users[i], commitments_[i]);
    }
}

// Pluggable: batch reveal for multiple users (onlyOwner or authorized)
function batchRevealEntropyForUsers(address[] calldata users, bytes[] calldata entropies) external payable onlyOwner {
    require(users.length == entropies.length, "Mismatched array lengths");
    uint256 totalFee = feePerEntropy * users.length;
    require(msg.value >= totalFee, "Insufficient fee");
    for (uint i = 0; i < users.length; i++) {
        bytes32 commitment = commitments[users[i]];
        if (commitment != keccak256(entropies[i])) revert InvalidCommitment();
        if (block.timestamp > commitmentTimestamps[users[i]] + 1 days) revert CommitmentExpired();
        delete commitments[users[i]];
        delete commitmentTimestamps[users[i]];
        emit EntropyRevealed(users[i], keccak256(entropies[i]));
        _feedEntropy(entropies[i]);
    }
    if (msg.value > totalFee) {
        payable(msg.sender).transfer(msg.value - totalFee);
    }
}

    function commitEntropy(bytes32 commitment) external override {
        if (authorizedCommitters[msg.sender] == false && msg.sender != owner()) revert UnauthorizedCommitter();
        if (commitment == bytes32(0)) revert InvalidInput();
        if (commitments[msg.sender] != bytes32(0)) revert CommitmentAlreadyExists();
        commitments[msg.sender] = commitment;
        commitmentTimestamps[msg.sender] = block.timestamp;
        emit EntropyCommitted(msg.sender, commitment);
    }

    function batchCommitEntropy(bytes32[] calldata commitments_) external override {
        if (authorizedCommitters[msg.sender] == false && msg.sender != owner()) revert UnauthorizedCommitter();
        if (commitments_.length > MAX_BATCH_COMMITS) revert TooManyCommitments();
        for (uint256 i = 0; i < commitments_.length; i++) {
            this.commitEntropy(commitments_[i]);
        }
        emit BatchCommitted(commitments_);
    }

    function revealEntropy(bytes calldata entropy) external payable override nonReentrant {
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

    function batchRevealEntropy(bytes[] calldata entropies) external payable override nonReentrant {
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

    function hasPendingCommit(address user) external view override returns (bool) {
        return commitments[user] != bytes32(0) && commitmentTimestamps[user] != 0;
    }

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

    // Prune old sponge steps (e.g., after off-chain export)
function pruneSpongeSteps(uint256 from, uint256 to) external onlyOwner {
    require(to > from && to <= stepCount, "Invalid range");
    for (uint256 i = from; i < to; i++) {
        delete spongeSteps[i];
    }
}

// Prune expired commitments (e.g., after timeout)
function pruneCommitments(address[] calldata users) external onlyOwner {
    for (uint i = 0; i < users.length; i++) {
        if (commitmentTimestamps[users[i]] != 0 && block.timestamp > commitmentTimestamps[users[i]] + 1 days) {
            delete commitments[users[i]];
            delete commitmentTimestamps[users[i]];
        }
    }
}

// Prune shards by index (if you want to free up storage)
function pruneShards(uint256 from, uint256 to) external onlyOwner {
    require(to > from && to <= shards.length, "Invalid range");
    for (uint256 i = from; i < to; i++) {
        delete shards[i];
    }
}

    function proposeMerkleRoot(bytes32 _root) external onlyOwner {
        if (_root == bytes32(0)) revert InvalidMerkleRoot();
        pendingMerkleRoot = _root;
        pendingMerkleRootTimestamp = block.timestamp;
        emit MerkleRootProposed(_root);
    }

    function applyMerkleRoot() external onlyOwner {
        if (pendingMerkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (block.timestamp < pendingMerkleRootTimestamp + merkleRootUpdateDelay) revert DelayNotElapsed();
        merkleRoot = pendingMerkleRoot;
        emit MerkleRootUpdated(merkleRoot);
        pendingMerkleRoot = bytes32(0);
        pendingMerkleRootTimestamp = 0;
    }

    function verifyLeaf(bytes32[] calldata proof, bytes32 leaf) external view returns (bool) {
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }

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

    function absorb(bytes memory paddedChunk) internal view returns (bytes memory newState) {
        newState = cloneBytes(internalState);
        for (uint256 i = 0; i < RATE && i < paddedChunk.length; i++) {
            newState[i] = bytes1(uint8(newState[i]) ^ uint8(paddedChunk[i]));
        }
    }

    function applyKeccakPadding(bytes memory inputChunk) internal pure returns (bytes memory padded) {
        uint256 len = inputChunk.length;
        uint256 padLen = RATE - (len % RATE);
        padded = new bytes(len + padLen);
        for (uint256 i = 0; i < len; i++) padded[i] = inputChunk[i];
        padded[len] = 0x01;
        padded[len + padLen - 1] = 0x80;
    }

    function findDiscardedBits(bytes memory original, bytes memory padded) internal pure returns (bytes memory) {
        if (padded.length <= original.length) return new bytes(0);
        uint256 diff = padded.length - original.length;
        bytes memory discarded = new bytes(diff);
        for (uint256 i = 0; i < diff; i++) {
            discarded[i] = padded[original.length + i];
        }
        return discarded;
    }

    function deployShard() external onlyOwner returns (address) {
        StorageShard shard = new StorageShard(msg.sender);
        shards.push(address(shard));
        emit ShardDeployed(address(shard));
        return address(shard);
    }

    function updateFee(uint256 newFee) external onlyOwner {
        if (newFee == 0) revert InvalidInput();
        feePerEntropy = newFee;
        emit FeeUpdated(newFee);
    }

    function updateMaxSteps(uint256 newMaxSteps) external onlyOwner {
        if (newMaxSteps == 0) revert InvalidInput();
        maxSteps = newMaxSteps;
        emit MaxStepsUpdated(newMaxSteps);
    }

    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        payable(owner()).transfer(balance);
    }

    function getState() external view returns (bytes memory) {
        return internalState;
    }

    function getStateHash() external view override returns (bytes32) {
        return keccak256(internalState);
    }

    function getStep(uint256 id) external view returns (SpongeStep memory) {
        return spongeSteps[id];
    }

    function slice(bytes memory data, uint256 start, uint256 len) internal pure returns (bytes memory) {
        if (start + len > data.length) revert InvalidInput();
        bytes memory sliced = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            sliced[i] = data[start + i];
        }
        return sliced;
    }

   


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

    receive() external payable {}
}


contract EntropyCoordinator is Ownable {
    IKeccakBlackBoxEngine[] public engines;

    event EngineAdded(address engine);
    event EngineRemoved(address engine);


    constructor() Ownable(msg.sender) {}

    function addEngine(address engine) external onlyOwner {
        require(engine != address(0), "Invalid engine address");
        for (uint i = 0; i < engines.length; i++) {
            require(address(engines[i]) != engine, "Engine already added");
        }
        engines.push(IKeccakBlackBoxEngine(engine));
        emit EngineAdded(engine);
    }

    function removeEngine(address engine) external onlyOwner {
        require(engine != address(0), "Invalid engine address");
        for (uint i = 0; i < engines.length; i++) {
            if (address(engines[i]) == engine) {
                engines[i] = engines[engines.length - 1];
                engines.pop();
                emit EngineRemoved(engine);
                return;
            }
        }
        revert("Engine not found");
    }




    function getEngines() external view returns (address[] memory) {
        address[] memory addrs = new address[](engines.length);
        for (uint i = 0; i < engines.length; i++) {
            addrs[i] = address(engines[i]);
        }
        return addrs;
    }

    function getEntropyFromEngines(
        bool[] calldata useEngines
    ) external view returns (bytes32) {
        require(useEngines.length == engines.length, "Mismatched array length");
        bytes memory data;
        for (uint i = 0; i < engines.length; i++) {
            if (useEngines[i]) {
                data = abi.encodePacked(data, engines[i].getStateHash());
            }
        }
        require(data.length > 0, "Must select at least one engine");
        return keccak256(data);
    }

 
    function commitEntropyAll(bytes32 commitment) external {
        for (uint i = 0; i < engines.length; i++) {
            engines[i].commitEntropy(commitment);
        }
    }

    function batchCommitEntropy(
        address[] calldata users,
        address[] calldata engines_,
        bytes32[] calldata commitments
    ) external {
        require(users.length == engines_.length && users.length == commitments.length, "Mismatched array lengths");
        for (uint i = 0; i < users.length; i++) {
            IKeccakBlackBoxEngine(engines_[i]).commitEntropy(commitments[i]);
        }
    }

    function batchCommitEntropyAll(
        bytes32[] calldata commitments
    ) external {
        for (uint i = 0; i < engines.length; i++) {
            engines[i].batchCommitEntropy(commitments);
        }
    }

    function revealEntropyAll(
        bytes calldata entropy
    ) external payable {
        uint256 totalFee = 0;
        bool[] memory hasPending = new bool[](engines.length);
        for (uint i = 0; i < engines.length; i++) {
            hasPending[i] = engines[i].hasPendingCommit(msg.sender);
            if (hasPending[i]) {
                totalFee += engines[i].feePerEntropy();
            }
        }
        require(msg.value >= totalFee, "Insufficient fee");

        for (uint i = 0; i < engines.length; i++) {
            if (hasPending[i]) {
                engines[i].revealEntropy{value: engines[i].feePerEntropy()}(entropy);
            }
        }

        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
    }

    function batchRevealEntropy(
        address[] calldata users,
        address[] calldata engines_,
        bytes[] calldata entropies
    ) external payable {
        require(users.length == engines_.length && users.length == entropies.length, "Mismatched array lengths");
        uint256 totalFee = 0;
        for (uint i = 0; i < users.length; i++) {
            IKeccakBlackBoxEngine engine = IKeccakBlackBoxEngine(engines_[i]);
            totalFee += engine.feePerEntropy();
        }
        require(msg.value >= totalFee, "Insufficient fee");
        for (uint i = 0; i < users.length; i++) {
            IKeccakBlackBoxEngine engine = IKeccakBlackBoxEngine(engines_[i]);
            engine.revealEntropy{value: engine.feePerEntropy()}(entropies[i]);
        }
        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
    }

    function batchRevealEntropyAll(
        bytes[] calldata entropies
    ) external payable {
        uint256 totalFee = 0;
        bool[] memory hasPending = new bool[](engines.length);
        for (uint i = 0; i < engines.length; i++) {
            hasPending[i] = engines[i].hasPendingCommit(msg.sender);
            if (hasPending[i]) {
                totalFee += engines[i].feePerEntropy() * entropies.length;
            }
        }
        require(msg.value >= totalFee, "Insufficient fee");

        for (uint i = 0; i < engines.length; i++) {
            if (hasPending[i]) {
                engines[i].batchRevealEntropy{value: engines[i].feePerEntropy() * entropies.length}(entropies);
            }
        }

        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
    }

    function getCombinedEntropy() external view returns (bytes32) {
        bytes memory data;
        for (uint i = 0; i < engines.length; i++) {
            data = abi.encodePacked(data, engines[i].getStateHash());
        }
        require(data.length > 0, "No engines");
        return keccak256(data);
    }

    function batchCommitEntropyForUsers(address[] calldata users, bytes32[] calldata commitments) external {
    require(users.length == commitments.length, "Mismatched array lengths");
    for (uint i = 0; i < engines.length; i++) {
        engines[i].batchCommitEntropyForUsers(users, commitments);
    }
}

function batchRevealEntropyForUsers(address[] calldata users, bytes[] calldata entropies) external payable {
    require(users.length == entropies.length, "Mismatched array lengths");
    uint256 totalFee = 0;
    for (uint i = 0; i < engines.length; i++) {
        totalFee += engines[i].feePerEntropy() * users.length;
    }
    require(msg.value >= totalFee, "Insufficient fee");
    for (uint i = 0; i < engines.length; i++) {
        engines[i].batchRevealEntropyForUsers{value: engines[i].feePerEntropy() * users.length}(users, entropies);
    }
    if (msg.value > totalFee) {
        payable(msg.sender).transfer(msg.value - totalFee);
    }
}
}

contract SimpleRandomNumberGenerator is Ownable {
    EntropyCoordinator public immutable coordinator;
    mapping(address => bytes32) public commitments;

    event RandomNumberRequested(address indexed user, string userSeed, bytes32 commitment);
    event RandomNumberGenerated(address indexed user, uint256 number);

    error InsufficientFee();
    error InvalidInput();
    error NoEngines();

    constructor(address _coordinator) Ownable(msg.sender) {
        require(_coordinator != address(0), "Invalid coordinator address");
        coordinator = EntropyCoordinator(_coordinator);
    }

    // Immediate mode
    function immediateRandomNumber(string calldata userSeed) external payable returns (uint256 number) {
        address[] memory engineAddrs = coordinator.getEngines();
        if (engineAddrs.length == 0) revert NoEngines();

        uint256 totalFee = 0;
        for (uint i = 0; i < engineAddrs.length; i++) {
            totalFee += IKeccakBlackBoxEngine(engineAddrs[i]).feePerEntropy();
        }
        if (msg.value < totalFee) revert InsufficientFee();
        if (bytes(userSeed).length == 0) revert InvalidInput();

        coordinator.revealEntropyAll{value: totalFee}(abi.encodePacked(userSeed, msg.sender, block.timestamp));
        bytes32 entropyHash = coordinator.getCombinedEntropy();
        number = (uint256(entropyHash) % 100) + 1;
        emit RandomNumberGenerated(msg.sender, number);

        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
    }

    // Commit step
    function commitRandomNumber(string calldata userSeed) external payable {
        address[] memory engineAddrs = coordinator.getEngines();
        if (engineAddrs.length == 0) revert NoEngines();

        uint256 totalFee = 0;
        for (uint i = 0; i < engineAddrs.length; i++) {
            totalFee += IKeccakBlackBoxEngine(engineAddrs[i]).feePerEntropy();
        }
        if (msg.value < totalFee) revert InsufficientFee();
        if (bytes(userSeed).length == 0) revert InvalidInput();

        bytes32 commitment = keccak256(abi.encodePacked(userSeed, msg.sender));
        commitments[msg.sender] = commitment;

        coordinator.commitEntropyAll(commitment);

        if (msg.value > totalFee) {
            payable(msg.sender).transfer(msg.value - totalFee);
        }
        emit RandomNumberRequested(msg.sender, userSeed, commitment);
    }

    // Reveal step
    function revealRandomNumber(string calldata userSeed) external returns (uint256 number) {
        bytes32 expectedCommitment = keccak256(abi.encodePacked(userSeed, msg.sender));
        require(commitments[msg.sender] == expectedCommitment, "No matching commitment");

        coordinator.revealEntropyAll(abi.encodePacked(userSeed, msg.sender));
        bytes32 entropyHash = coordinator.getCombinedEntropy();
        number = (uint256(entropyHash) % 100) + 1;
        emit RandomNumberGenerated(msg.sender, number);

        delete commitments[msg.sender];
    }
}
