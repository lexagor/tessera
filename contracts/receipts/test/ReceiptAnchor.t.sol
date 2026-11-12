// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ReceiptAnchor} from "../src/ReceiptAnchor.sol";

contract ReceiptAnchorTest is Test {
    ReceiptAnchor anchor;

    function setUp() public {
        anchor = new ReceiptAnchor();
    }

    function test_anchor_and_latest_root() public {
        bytes32 tenant = keccak256("tenant");
        bytes32 root = keccak256("root");
        uint256 index = anchor.anchor(tenant, root, 10);
        assertEq(index, 0);
        assertEq(anchor.latestRoot(tenant), root);
        assertEq(anchor.batchCount(tenant), 1);
    }

    function test_revert_on_empty_batch() public {
        vm.expectRevert(ReceiptAnchor.EmptyBatch.selector);
        anchor.anchor(keccak256("tenant"), bytes32(0), 1);
    }

    function test_verify_latest_single_leaf() public {
        bytes32 tenant = keccak256("tenant");
        bytes32 leaf = keccak256("leaf");
        anchor.anchor(tenant, leaf, 1);
        bytes32[] memory proof = new bytes32[](0);
        assertTrue(anchor.verifyLatest(tenant, leaf, proof));
    }

    // ── Merkle convention helpers (mirror the Rust `merkle` module) ────────────

    function _pair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    /// Recomputes, in Solidity, the root that `apps/broker/src/merkle.rs`
    /// (`cross_language_root_matches_solidity`) produces for the same leaves.
    function test_cross_language_root() public pure {
        bytes32 l0 = keccak256(bytes("receipt-0"));
        bytes32 l1 = keccak256(bytes("receipt-1"));
        bytes32 l2 = keccak256(bytes("receipt-2"));
        bytes32 l3 = keccak256(bytes("receipt-3"));
        bytes32 root = _pair(_pair(l0, l1), _pair(l2, l3));
        assertEq(root, 0x9b273f5e529ec8c336d2e2f6a1b4cf3703f0ae1c460cad01a1b1851d870c22e5);
    }

    function test_verify_proof_sorted_pairs() public {
        bytes32 tenant = keccak256("tenant");
        bytes32 l0 = keccak256("a");
        bytes32 l1 = keccak256("b");
        bytes32 root = _pair(l0, l1);

        anchor.anchor(tenant, root, 2);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = l1;
        assertTrue(anchor.verifyLatest(tenant, l0, proof));
        assertTrue(anchor.verifyProof(root, l0, proof));
        assertFalse(anchor.verifyProof(root, keccak256("evil"), proof));
    }
}
