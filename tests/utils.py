import logging
from pathlib import Path
from wake.testing import *
from wake.testing.fuzzing import random_bytes
from dataclasses import dataclass

from pytypes.core.contracts._0_8_9.proxy.OssifiableProxy import OssifiableProxy
from pytypes.tests.migrated_contracts.NodeOperatorsRegistryMigrated import NodeOperatorsRegistryMigrated
from pytypes.core.contracts._0_8_9.utils.access.AccessControl import AccessControl

from .beacon import BeaconChain
from .fork_data import *

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def revert_handler(e: RevertError):
    if e.tx is not None:
        print(e.tx.call_trace)


def sig_to_compact(r, s, yParity):
    if isinstance(yParity, bytes):
        yParity_int = int.from_bytes(yParity, byteorder='big')
    else:
        yParity_int = yParity

    if isinstance(s, bytes):
        s_int = int.from_bytes(s, byteorder='big')
    else:
        s_int = s

    if yParity_int == 27:
        yParity_int = 0
    elif yParity_int == 28:
        yParity_int = 1

    vs = (yParity_int << 255) | s_int

    try:
        vs_bytes = vs.to_bytes(32, byteorder='big')
    except OverflowError:
        raise OverflowError("Combined integer too large to fit in 32 bytes")

    return (r, vs_bytes)

## for aragon dao deployment
def appId(name: str, val: int = 0)->bytes32:
    return keccak256(f"{name}.aragonpm.test{val}".encode('utf-8'))

def update_locator(admin: Account, config: LidoLocator.Config):
    new_impl = LidoLocator.deploy(config)
    OssifiableProxy(LIDO_LOCATOR).proxy__upgradeTo(new_impl, from_=admin)

def deploy_staking_router(admin: Account, sr_module_manager: Account, sr_rewards_reporter: Account, sr_exited_validators_reporter: Account, sr_unsafe_role: Account, sr_unvetting_role: Account, deposit_contract: Account, withdrawal_address: Account, lido: Account):
    sr_impl = StakingRouter.deploy(deposit_contract)
    sr_proxy = OssifiableProxy.deploy(
        sr_impl,
        admin,
        b"",
    )
    sr = StakingRouter(sr_proxy)
    sr.initialize(admin, lido, withdrawal_address)
    sr.grantRole(sr.STAKING_MODULE_MANAGE_ROLE(), sr_module_manager)
    sr.grantRole(sr.REPORT_REWARDS_MINTED_ROLE(), LIDO)
    sr.grantRole(sr.REPORT_REWARDS_MINTED_ROLE(), sr_rewards_reporter)
    sr.grantRole(sr.REPORT_EXITED_VALIDATORS_ROLE(), sr_exited_validators_reporter)
    sr.grantRole(sr.UNSAFE_SET_EXITED_VALIDATORS_ROLE(), sr_unsafe_role)
    sr.grantRole(sr.STAKING_MODULE_UNVETTING_ROLE(), sr_unvetting_role)
    sr.grantRole(sr.MANAGE_WITHDRAWAL_CREDENTIALS_ROLE(), admin)
    return sr

def deploy_deposit_security_module(admin: Account, lido: Account, deposit_contract: Account, staking_router: Account, pivpb: int, mopu: int):
    return DepositSecurityModule.deploy(lido, deposit_contract, staking_router, pivpb, mopu)

def deploy_node_operator_registry(lib: Account, no_manager: Account, no_limiter: Account, staking_router: Account, stuck_penalty_delay: int, test_old_solidity: bool, app_id: bytes32):
    if test_old_solidity:
        code_wo_lib = (Path(__file__).parent.parent / "bin" / "NodeOperatorsRegistry.bin" ).read_text()
        code_w_lib = code_wo_lib.replace("__core/contracts/common/lib/MinFirstAl__", str(lib.address)[2:])
        code = bytes.fromhex(code_w_lib)
        nor_impl = chain.deploy(code)
    else:
        nor_impl = NodeOperatorsRegistryMigrated.deploy()

    tx = LIDO_DAO.newAppInstance_(app_id, nor_impl, b'', False, from_=ARAGON_VOTING)
    e = next((e for e in tx.events if isinstance(e, Kernel.NewAppProxy)), None)
    assert e is not None, "Expected event does not exist"
    nor = NodeOperatorsRegistryMigrated(e.proxy)
    assert nor.kernel() == LIDO.kernel()

    ARAGON_ACL.createPermission(no_manager, nor, nor.MANAGE_NODE_OPERATOR_ROLE(), ARAGON_VOTING, from_=ARAGON_VOTING)
    ARAGON_ACL.createPermission(no_limiter, nor, nor.SET_NODE_OPERATOR_LIMIT_ROLE(), ARAGON_VOTING, from_=ARAGON_VOTING)
    ARAGON_ACL.createPermission(staking_router, nor, nor.STAKING_ROUTER_ROLE(), ARAGON_VOTING, from_=ARAGON_VOTING)
    nor.initialize(LIDO_LOCATOR, keccak256(b'NOR'), stuck_penalty_delay)

    access_control_overwrite(BURNER, BURNER.REQUEST_BURN_SHARES_ROLE(), nor)

    return nor


def deploy_accounting_oracle(admin: Account, report_submitter: Account, beacon_chain: BeaconChain) -> AccountingOracle:
    accounting_oracle_impl = AccountingOracle.deploy(
        lidoLocator=LIDO_LOCATOR,
        lido=LIDO,
        legacyOracle=LEGACY_ORACLE,
        secondsPerSlot=beacon_chain.SECONDS_PER_SLOT,
        genesisTime=beacon_chain.GENESIS_TIME,
        from_=admin,
    )
    accounting_oracle = OssifiableProxy.deploy(
        accounting_oracle_impl,
        admin,
        b"",
    )
    accounting_oracle = AccountingOracle(accounting_oracle)

    return accounting_oracle

def deploy_validator_exit_bus_oracle(admin: Account, report_submitter: Account) -> ValidatorsExitBusOracle:
    validators_exit_bus_oracle_impl = ValidatorsExitBusOracle.deploy(
        secondsPerSlot=SECONDS_PER_SLOT,
        genesisTime=GENESIS_TIME,
        lidoLocator=LIDO_LOCATOR,
        from_=admin,
    )
    validators_exit_bus_oracle = OssifiableProxy.deploy(
        validators_exit_bus_oracle_impl,
        admin,
        b"",
    )

    validators_exit_bus_oracle = ValidatorsExitBusOracle(validators_exit_bus_oracle)
    return validators_exit_bus_oracle


def deploy_hash_consensus(report_processor: Address, quarum_member: Account, admin: Account, beacon_chain: BeaconChain) -> HashConsensus:
    hc = HashConsensus.deploy(
        slotsPerEpoch=beacon_chain.SLOTS_PER_EPOCH,
        secondsPerSlot=beacon_chain.SECONDS_PER_SLOT,
        genesisTime=beacon_chain.GENESIS_TIME,
        epochsPerFrame=beacon_chain.EPOCHS_PER_FRAME,
        fastLaneLengthSlots=FAST_LANE_LENGTH_SLOTS,
        admin=admin,
        reportProcessor=report_processor,
        from_=admin,
    )
    hc.grantRole(hc.MANAGE_MEMBERS_AND_QUORUM_ROLE(), admin, from_=admin)
    hc.addMember(
        quarum_member,
        1,
        from_=admin
    )
    assert hc.getIsMember(quarum_member) == True
    return hc

def access_control_overwrite(target: AccessControl, roles: bytes32, user: Account):
    base_slot = keccak256(b"openzeppelin.AccessControl._roles")
    outer_mapping_slot = keccak256(abi.encode(roles ,base_slot))
    inner_mapping_slot = keccak256(abi.encode(user.address, outer_mapping_slot))
    chain.chain_interface.set_storage_at(
        str(target.address),
        int.from_bytes(inner_mapping_slot),
        abi.encode(True)
    )
    assert target.hasRole(roles, user.address) == True, "wrong slot probably"
