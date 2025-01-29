# Tests for Lido Community Staking Module & Staking Router
This repository serves as an example of tests written in a development and testing framework called [Wake](https://github.com/Ackee-Blockchain/wake).

![horizontal splitter](https://github.com/Ackee-Blockchain/wake-detect-action/assets/56036748/ec488c85-2f7f-4433-ae58-3d50698a47de)

## Setup

1. Clone this repository
2. `git submodule update --init --recursive` if not cloned with `--recursive`
3. `cd core && yarn install && cd ..` to install Staking Router dependencies
4. `cd csm && yarn install && cd ..` to install CSM dependencies
5. `cd easy-track && yarn install && cd ..` to install EasyTrack dependencies
6. `./compile_old_solidity.sh` to compile contracts with older Solidity versions not supported by Wake

## Running fuzz tests

1. `wake up pytypes` to generate pytypes
2. `wake test tests/test_csm_fuzz.py` to run CSM fuzz test (see [tests](tests/) for other tests)

## Running deployment verification

1. `wake --config wake-deployment-verification.toml up pytypes` to generate pytypes
2. `wake test tests/test_csm_deployment.py` to perform deployment verification for CSM
3. `wake test tests/test_sr_deployment.py` to perform deployment verification for Staking Router

Tested with `wake` version `4.14.1` and `anvil` version `anvil 0.2.0 (00efa0d 2024-12-09T00:29:01.834942000Z)`. Fuzz tests expect a local Ethereum mainnet node running at http://localhost:8545 synchronized to the block `20935461` or later.