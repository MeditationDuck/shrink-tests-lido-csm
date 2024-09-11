/*
 * SPDX-License-Identifier:    MIT
 */

pragma solidity ^0.6.2;


interface IForwarder {
    function isForwarder() external pure returns (bool);

    // TODO: this should be external
    // See https://github.com/ethereum/solidity/issues/4832
    function canForward(address sender, bytes calldata evmCallScript) external view returns (bool);

    // TODO: this should be external
    // See https://github.com/ethereum/solidity/issues/4832
    function forward(bytes calldata evmCallScript) external;
}
