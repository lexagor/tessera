// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title ReceiptAnchor
/// @notice Anchors Merkle roots of Tessera receipt batches so that any receipt can be
///         verified against an immutable, append-only record without revealing payloads.
/// @dev Status: scaffold. Batches are append-only; roots are keyed by tenant.
contract ReceiptAnchor {
    struct Batch {
        bytes32 merkleRoot;
        uint64 timestamp;
        uint64 count;
    }

    /// tenant => index => batch
    mapping(bytes32 => mapping(uint256 => Batch)) public batches;
    /// tenant => number of anchored batches
    mapping(bytes32 => uint256) public batchCount;

    event Anchored(
        bytes32 indexed tenant,
        uint256 indexed index,
        bytes32 merkleRoot,
        uint64 timestamp,
        uint64 count
    );

    error EmptyBatch();
    error NotAuthorized();

    modifier onlyTenant(bytes32 tenant) {
        // TODO: restrict to the tenant's registered signing key via an access registry.
        _;
    }

    /// @notice Anchor a new batch root for a tenant.
    function anchor(bytes32 tenant, bytes32 merkleRoot, uint64 count)
        external
        onlyTenant(tenant)
        returns (uint256 index)
    {
        if (merkleRoot == bytes32(0) || count == 0) revert EmptyBatch();
        index = batchCount[tenant]++;
        batches[tenant][index] = Batch({
            merkleRoot: merkleRoot,
            timestamp: uint64(block.timestamp),
            count: count
        });
        emit Anchored(tenant, index, merkleRoot, uint64(block.timestamp), count);
    }

    /// @notice Return the most recent anchored root for a tenant.
    function latestRoot(bytes32 tenant) external view returns (bytes32) {
        uint256 n = batchCount[tenant];
        if (n == 0) return bytes32(0);
        return batches[tenant][n - 1].merkleRoot;
    }

    /// @notice Verify a leaf against the latest root for a tenant, given a Merkle proof.
    function verifyLatest(bytes32 tenant, bytes32 leaf, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        uint256 n = batchCount[tenant];
        if (n == 0) return false;
        return _verify(proof, batches[tenant][n - 1].merkleRoot, leaf);
    }

    /// @notice Verify a leaf against an arbitrary root, given a Merkle proof.
    function verifyProof(bytes32 root, bytes32 leaf, bytes32[] calldata proof)
        external
        pure
        returns (bool)
    {
        return _verify(proof, root, leaf);
    }

    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool)
    {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed <= p
                ? keccak256(abi.encodePacked(computed, p))
                : keccak256(abi.encodePacked(p, computed));
        }
        return computed == root;
    }
}
