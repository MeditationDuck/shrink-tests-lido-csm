/*
 * SPDX-License-Identifier:    MIT
 */

pragma solidity ^0.6.2;

import "../../common/Autopetrified.sol";
import "../IEVMScriptExecutor.sol";


abstract contract BaseEVMScriptExecutor is IEVMScriptExecutor, Autopetrified {
    uint256 internal constant SCRIPT_START_LOCATION = 4;
}
