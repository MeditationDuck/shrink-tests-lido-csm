// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "../../csm/src/lib/SSZ.sol";


contract MockSZZ{
    using SSZ for *;

    function testVerifyProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf,
        GIndex gIndex
    ) external view {
        // Call the SSZ library's verifyProof function
        SSZ.verifyProof(proof, root, leaf, gIndex);
    }
}