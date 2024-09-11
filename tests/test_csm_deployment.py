import wake.deployment
from wake.testing import *

from pytypes.csm.src.CSModule import CSModule
from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.CSEarlyAdoption import CSEarlyAdoption
from pytypes.csm.src.CSFeeDistributor import CSFeeDistributor
from pytypes.csm.src.CSFeeOracle import CSFeeOracle
from pytypes.csm.src.CSVerifier import CSVerifier
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy
from pytypes.csm.src.lib.NOAddresses import NOAddresses
from pytypes.csm.src.lib.AssetRecovererLib import AssetRecovererLib
from pytypes.csm.src.lib.QueueLib import QueueLib
from pytypes.csm.src.lib.baseoracle.HashConsensus import HashConsensus
from pytypes.easytrack.contracts.EVMScriptFactories.CSMSettleELStealingPenalty import CSMSettleElStealingPenalty


pre_chain = Chain()
post_chain = wake.deployment.Chain()


@pre_chain.connect(fork="http://localhost:8545@20935461")
@post_chain.connect("http://localhost:8545")
def test_deployment():
    locator = Account("C1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb", chain=pre_chain)
    sender = Account("0xD87c8526faCecfD27cec98A629a3b7876B2cda11", chain=pre_chain)
    owner = Account("3e40d73eb977dc6a537af587d48316fee66e9c8c", chain=pre_chain)
    st_eth = Account("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", chain=pre_chain)
    lib_creator = Account("0x4e59b44847b379578588920cA78FbF26c0B4956C", chain=pre_chain)

    pre_chain.default_tx_account = sender

    asset_recoverer_lib = AssetRecovererLib(
        lib_creator.transact(bytes32(0) + AssetRecovererLib.get_creation_code()).return_value.hex(),
        chain=pre_chain
    )
    asset_recoverer_lib2 = AssetRecovererLib("0xa74528edc289b1a597Faf83fCfF7eFf871Cc01D9", chain=post_chain)
    assert asset_recoverer_lib.code == asset_recoverer_lib2.code
    assert asset_recoverer_lib.address == asset_recoverer_lib2.address

    no_addresses = NOAddresses(
        lib_creator.transact(bytes32(0) + NOAddresses.get_creation_code()).return_value.hex(),
        chain=pre_chain
    )
    no_addresses2 = NOAddresses("0xF8E5de8bAf8Ad7C93DCB61D13d00eb3D57131C72", chain=post_chain)
    assert no_addresses.code == no_addresses2.code
    assert no_addresses.address == no_addresses2.address

    queue_lib = QueueLib(
        lib_creator.transact(bytes32(1) + QueueLib.get_creation_code()).return_value.hex(),
        chain=pre_chain
    )
    queue_lib2 = QueueLib("0xD19B40Cb5401f1413D014A56529f03b3452f70f9", chain=post_chain)
    assert queue_lib.code == queue_lib2.code
    assert queue_lib.address == queue_lib2.address

    cs_module = CSModule.deploy(
        bytes.fromhex("636f6d6d756e6974792d6f6e636861696e2d7631000000000000000000000000"),
        32,
        100000000000000000,
        12,
        100000000000000000,
        locator,
        chain=pre_chain,
        assetRecovererLib=asset_recoverer_lib2.address,
        queueLib=queue_lib2.address,
        nOAddresses=no_addresses2.address
    )
    cs_module2 = CSModule("0x8daea53b17a629918cdfab785c5c74077c1d895b", chain=post_chain)
    assert cs_module.code == cs_module2.code
    assert cs_module.address == cs_module2.address

    cs_module_proxy = OssifiableProxy.deploy(cs_module, owner, b"", chain=pre_chain)
    cs_module_proxy2 = OssifiableProxy("0xdA7dE2ECdDfccC6c3AF10108Db212ACBBf9EA83F", chain=post_chain)
    assert cs_module_proxy.code == cs_module_proxy2.code
    assert cs_module_proxy.address == cs_module_proxy2.address

    cs_accounting = CSAccounting.deploy(locator, cs_module_proxy, 10, 2419200, 31536000, chain=pre_chain, assetRecovererLib=asset_recoverer_lib2.address)
    cs_accounting2 = CSAccounting("0x71FCD2a6F38B644641B0F46c345Ea03Daabf2758", chain=post_chain)
    assert cs_accounting.code == cs_accounting2.code
    assert cs_accounting.address == cs_accounting2.address

    cs_accounting_proxy = OssifiableProxy.deploy(cs_accounting, owner, b"", chain=pre_chain)
    cs_accounting_proxy2 = OssifiableProxy("0x4d72BFF1BeaC69925F8Bd12526a39BAAb069e5Da", chain=post_chain)
    assert cs_accounting_proxy.code == cs_accounting_proxy2.code
    assert cs_accounting_proxy.address == cs_accounting_proxy2.address

    cs_fee_oracle = CSFeeOracle.deploy(12, 1606824023, chain=pre_chain, assetRecovererLib=asset_recoverer_lib2.address)
    cs_fee_oracle2 = CSFeeOracle("0x919ac5C6c62B6ef7B05cF05070080525a7B0381E", chain=post_chain)
    assert cs_fee_oracle.code == cs_fee_oracle2.code
    assert cs_fee_oracle.address == cs_fee_oracle2.address

    cs_fee_oracle_proxy = OssifiableProxy.deploy(cs_fee_oracle, owner, b"", chain=pre_chain)
    cs_fee_oracle_proxy2 = OssifiableProxy("0x4D4074628678Bd302921c20573EEa1ed38DdF7FB", chain=post_chain)
    assert cs_fee_oracle_proxy.code == cs_fee_oracle_proxy2.code
    assert cs_fee_oracle_proxy.address == cs_fee_oracle_proxy2.address

    cs_fee_distributor = CSFeeDistributor.deploy(st_eth, cs_accounting_proxy, cs_fee_oracle_proxy, chain=pre_chain, assetRecovererLib=asset_recoverer_lib2.address)
    cs_fee_distributor2 = CSFeeDistributor("0x17Fc610ecbbAc3f99751b3B2aAc1bA2b22E444f0", chain=post_chain)
    assert cs_fee_distributor.code == cs_fee_distributor2.code
    assert cs_fee_distributor.address == cs_fee_distributor2.address

    cs_fee_distributor_proxy = OssifiableProxy.deploy(cs_fee_distributor, owner, b"", chain=pre_chain)
    cs_fee_distributor_proxy2 = OssifiableProxy("0xD99CC66fEC647E68294C6477B40fC7E0F6F618D0", chain=post_chain)
    assert cs_fee_distributor_proxy.code == cs_fee_distributor_proxy2.code
    assert cs_fee_distributor_proxy.address == cs_fee_distributor_proxy2.address

    cs_verifier = CSVerifier.deploy(
        Address("0xB9D7934878B5FB9610B3fE8A5e441e8fad7E293f"),
        cs_module_proxy,
        32,
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000e1c004"),
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000e1c004"),
        bytes.fromhex("0000000000000000000000000000000000000000000000000056000000000028"),
        bytes.fromhex("0000000000000000000000000000000000000000000000000056000000000028"),
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000003b00"),
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000003b00"),
        8626176,
        8626176,
        chain=pre_chain,
    )
    cs_verifier2 = CSVerifier("0x3Dfc50f22aCA652a0a6F28a0F892ab62074b5583", chain=post_chain)
    assert cs_verifier.code == cs_verifier2.code
    assert cs_verifier.address == cs_verifier2.address

    sender.nonce += 4

    cs_early_adoption = CSEarlyAdoption.deploy(bytes.fromhex("359e02c5c065c682839661c9bdfaf38db472629bf5f7a7e8f0261b31dc9332c2"), 1, cs_module_proxy, chain=pre_chain)
    cs_early_adoption2 = CSEarlyAdoption("0x3D5148ad93e2ae5DedD1f7A8B3C19E7F67F90c0E", chain=post_chain)
    assert cs_early_adoption.code == cs_early_adoption2.code
    assert cs_early_adoption.address == cs_early_adoption2.address

    sender.nonce += 2

    hash_consensus = HashConsensus.deploy(32, 12, 1606824023, 6300, 1800, owner, cs_fee_oracle_proxy, chain=pre_chain)
    hash_consensus2 = HashConsensus("0x71093efF8D8599b5fA340D665Ad60fA7C80688e4", chain=post_chain)
    assert hash_consensus.code == hash_consensus2.code
    assert hash_consensus.address == hash_consensus2.address

    sender.nonce += 31

    el_stealing_evm_script = CSMSettleElStealingPenalty.deploy(Address("c52fc3081123073078698f1eac2f1dc7bd71880f"), cs_module_proxy, chain=pre_chain)
    el_stealing_evm_script2 = CSMSettleElStealingPenalty("0xF6B6E7997338C48Ea3a8BCfa4BB64a315fDa76f4", chain=post_chain)
    assert el_stealing_evm_script.code[:-53] == el_stealing_evm_script2.code[:-53]
    assert el_stealing_evm_script.address == el_stealing_evm_script2.address
