/*
 * SPDX-License-Identifier:    MIT
 */

pragma solidity ^0.6.2;


abstract contract ERCProxy {
    uint256 internal constant FORWARDING = 1;
    uint256 internal constant UPGRADEABLE = 2;

    function proxyType() public virtual pure returns (uint256 proxyTypeId);
    function implementation() public virtual view returns (address codeAddr);
}
