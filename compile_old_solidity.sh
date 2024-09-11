#!/bin/bash

wake svm use 0.4.24
wake-solc --bin -o bin '@aragon/=core/node_modules/@aragon/' \
    'openzeppelin-solidity/=core/node_modules/openzeppelin-solidity/' \
    core/node_modules/openzeppelin-solidity/contracts/token/ERC20/IERC20.sol \
    core/contracts/0.4.24/Lido.sol \
    core/contracts/0.4.24/nos/NodeOperatorsRegistry.sol \
    core/node_modules/@aragon/os/contracts/apps/AragonApp.sol \
    core/node_modules/@aragon/os/contracts/lib/math/SafeMath.sol \
    core/node_modules/@aragon/os/contracts/common/UnstructuredStorage.sol \
    core/node_modules/@aragon/os/contracts/kernel/Kernel.sol \
    core/node_modules/@aragon/os/contracts/acl/ACL.sol \
    core/node_modules/@aragon/os/contracts/factory/DAOFactory.sol \
    core/node_modules/@aragon/os/contracts/factory/EVMScriptRegistryFactory.sol \
    core/contracts/common/lib/Math256.sol \
    core/contracts/common/lib/MinFirstAllocationStrategy.sol \
    core/contracts/common/interfaces/ILidoLocator.sol \
    core/contracts/common/interfaces/IBurner.sol \
    core/contracts/0.4.24/lib/SigningKeys.sol \
    core/contracts/0.4.24/lib/Packed64x4.sol \
    core/contracts/0.4.24/utils/Versioned.sol \
    --allow-paths "" --optimize --optimize-runs 200 --overwrite --evm-version constantinople
