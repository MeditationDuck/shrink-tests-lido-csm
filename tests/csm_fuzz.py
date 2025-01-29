from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Tuple
from enum import Enum, auto

from ordered_set import OrderedSet
from wake.testing import *
from wake.testing.fuzzing import *
from pytypes.core.contracts._0_8_9.WithdrawalQueue import WithdrawalQueue
from pytypes.core.contracts._0_8_9.WithdrawalQueueERC721 import WithdrawalQueueERC721
from pytypes.csm.node_modules.openzeppelin.contracts.token.ERC20.extensions.IERC20Permit import IERC20Permit
from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.CSEarlyAdoption import CSEarlyAdoption
from pytypes.csm.src.CSFeeDistributor import CSFeeDistributor
from pytypes.csm.src.CSFeeOracle import CSFeeOracle
from pytypes.csm.src.CSModule import CSModule
from pytypes.csm.src.CSVerifier import CSVerifier
from pytypes.csm.src.interfaces.IStETH import IStETH
from pytypes.csm.src.interfaces.IWstETH import IWstETH
from pytypes.csm.src.interfaces.IWithdrawalQueue import IWithdrawalQueue
from pytypes.csm.src.interfaces.ILido import ILido
from pytypes.csm.src.interfaces.ILidoLocator import ILidoLocator
from pytypes.csm.src.interfaces.IBurner import IBurner
from pytypes.csm.src.interfaces.ICSModule import NodeOperatorManagementProperties
from pytypes.csm.src.lib.baseoracle.HashConsensus import HashConsensus
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy
from pytypes.csm.src.lib.AssetRecovererLib import AssetRecovererLib
from pytypes.csm.src.lib.NOAddresses import NOAddresses
from pytypes.csm.src.lib.QueueLib import QueueLib
from pytypes.csm.src.lib.Types import BeaconBlockHeader, Withdrawal, Validator
from pytypes.core.contracts._0_6_11.deposit_contract import IDepositContract
from pytypes.tests.migrated_contracts.LidoMigrated import StETH, LidoMigrated
from abc import ABC, abstractmethod

from .merkle_tree import MerkleTree
from .utils import logger

CSM_MAX_COUNT = 1

DEFAULT_CURVE = uint(0)
EARLY_ADOPTION_CURVE = uint(1)
ST_ETH = IStETH("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
WST_ETH = IWstETH("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0")

NO_AVG_COUNT = 1

SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12
# could hold some amount after distribute rewards to staking module and before distribute node operators.
# and default reward distribution in csm is each 28 days, I temporary modified frame size shorter
# EPOCHS_PER_FRAME = 225 * 28  # 28 days by default
EPOCHS_PER_FRAME = 225*2
GENESIS_TIME = 1606824023
MODULE_TYPE = random_bytes(32)

LIDO_LOCATOR = ILidoLocator("0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")
LIDO_TREASURY = Account("0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c")
MAX_KEYS_PER_OPERATOR_EA = 10
MAX_CURVE_LENGTH = 10
MIN_BOND_LOCK_RETENTION_PERIOD = 4 * 7 * 24 * 60 * 60  # 4 weeks
MAX_BOND_LOCK_RETENTION_PERIOD = 365 * 24 * 60 * 60  # 1 year
KEY_REMOVAL_CHARGE = Wei.from_ether(0.05)
MAX_KEY_REMOVAL_CHARGE = Wei.from_ether(0.1)
FAST_LANE_LENGTH_SLOTS = 0
MIN_SLASHING_PENALTY_QUOTIENT = 32
AVG_PERF_LEEWAY_BP = 500  # 5%
EL_REWARDS_STEALING_FINE = Wei.from_ether(0.1)

DEFAULT_BOND_CURVE = [
    Wei.from_ether(2),
    Wei.from_ether(1.9),
    Wei.from_ether(1.8),
    Wei.from_ether(1.7),
    Wei.from_ether(1.6),
    Wei.from_ether(1.5),
]
CUMULATIVE_DEFAULT_BOND_CURVE = [sum(DEFAULT_BOND_CURVE[:i + 1]) for i in range(len(DEFAULT_BOND_CURVE))]

EA_BOND_CURVE = [
    Wei.from_ether(1.5),
    Wei.from_ether(1.9),
    Wei.from_ether(1.8),
    Wei.from_ether(1.7),
    Wei.from_ether(1.6),
    Wei.from_ether(1.5),
]
CUMULATIVE_EA_BOND_CURVE = [sum(EA_BOND_CURVE[:i + 1]) for i in range(len(EA_BOND_CURVE))]


def hash_beacon_block_header(header: BeaconBlockHeader) -> bytes:
    tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
    for leaf in [
        header.slot.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        header.proposerIndex.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        header.parentRoot,
        header.stateRoot,
        header.bodyRoot,
        bytes32(0),  # dummy for power of 2 number of leaves
        bytes32(0),  # dummy for power of 2 number of leaves
        bytes32(0),  # dummy for power of 2 number of leaves
    ]:
        tree.add_leaf(leaf)
    return tree.root


def hash_validator(validator: Validator) -> bytes:
    tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)

    pubkey_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
    pubkey_tree.add_leaf(validator.pubkey[:32])
    pubkey_tree.add_leaf(validator.pubkey[32:] + b"\x00" * 16)

    for leaf in [
        pubkey_tree.root,
        validator.withdrawalCredentials,
        validator.effectiveBalance.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        validator.slashed.to_bytes(1, "little") + b"\x00" * 31,  # bool
        validator.activationEligibilityEpoch.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        validator.activationEpoch.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        validator.exitEpoch.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        validator.withdrawableEpoch.to_bytes(8, "little") + b"\x00" * 24,  # uint64
    ]:
        tree.add_leaf(leaf)
    return tree.root


def hash_withdrawal(withdrawal: Withdrawal) -> bytes:
    tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
    for leaf in [
        withdrawal.index.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        withdrawal.validatorIndex.to_bytes(8, "little") + b"\x00" * 24,  # uint64
        bytes(withdrawal.withdrawalAddress) + b"\x00" * 12,
        withdrawal.amount.to_bytes(8, "little") + b"\x00" * 24,  # uint64
    ]:
        tree.add_leaf(leaf)
    return tree.root

class KeyState(Enum):
    Added = 1
    Vetted = 2
    Deposited = 3
    Stucked = 4
    Exited = 5

@dataclass
class KeyInfo:
    pkey: bytes
    signature: bytes
    key_state: KeyState


@dataclass
class Permit:
    owner: Address
    spender: Address
    value: uint
    nonce: uint
    deadline: uint


@dataclass
class NodeOperator:
    id: int
    total_keys_count: int
    deposited_keys: int # exclude withdrawn
    deposited_keys_count: int # sum of deposited_keys and withdrawn_keys
    vetted_keys_count: int
    withdrawn_keys: int
    exited_keys_count: int
    stuck_keys_count: int
    keys_bytes: List[bytes]
    signatures: List[bytes]
    manager: Account
    rewards_account: Account
    target_limit: uint
    target_limit_mode: uint
    bond_curve: List[int]  # in ETH
    bond_shares: uint  # in stETH shares
    locked_bond: uint  # in ETH
    total_rewards: uint  # in stETH shares
    claimed_rewards: uint  # in stETH shares
    lock_expiry: uint  # timestamp
    slashed: Dict[int, bool]  # validator key index -> slashed
    withdrawn: Dict[int, bool]  # validator key index -> withdrawn
    keys: List[KeyInfo]

@dataclass
class QueueItem:
    no_id: int
    keys_count: int


@dataclass
class Csm:
    id: int
    hash_consenus: HashConsensus
    accounting: CSAccounting
    early_adoption: CSEarlyAdoption
    fee_distributor: CSFeeDistributor
    fee_oracle: CSFeeOracle
    verifier: CSVerifier
    module: CSModule

    ea_tree: MerkleTree
    ea_accounts: OrderedSet[Account]
    admin: Account
    bond_lock_retention_period: uint
    consensus_version: uint
    steth_domain: Eip712Domain
    wsteth_domain: Eip712Domain
    charge_penalty_recipient: Account

    node_operators: Dict[int, NodeOperator]
    consensus_members: OrderedSet[Account]
    initial_epoch: int
    consensus_quorum: int
    last_report_ref_slot: int
    rewards_tree: MerkleTree
    queue: deque[QueueItem]
    nonce: uint
    key_removal_charge: uint
    total_exited_keys_count: int


def timestamp_to_slot(timestamp: uint) -> uint:
    return (timestamp - GENESIS_TIME) // SECONDS_PER_SLOT


def timestamp_to_epoch(timestamp: uint) -> uint:
    return timestamp_to_slot(timestamp) // SLOTS_PER_EPOCH


class CsmFuzzTest(FuzzTest):
    burner: IBurner
    el_rewards_vault: Account

    # accounting
    balances: Dict[Account, uint]
    shares: Dict[Account, uint]

    csms_initial_balance: Dict[Account, uint]
    csms: Dict[int, Csm]

    withdrawal_queue: WithdrawalQueueERC721

    def pre_sequence(self) -> None:
        self.burner = IBurner(LIDO_LOCATOR.burner())
        self.el_rewards_vault = Account(LIDO_LOCATOR.elRewardsVault())

        NOAddresses.deploy()
        AssetRecovererLib.deploy()
        QueueLib.deploy()

        self.balances = defaultdict(int)
        self.shares = defaultdict(int)
        for acc in [LIDO_TREASURY, self.burner, self.el_rewards_vault] + list(chain.accounts):
            self.balances[acc] = acc.balance
            self.shares[acc] = ST_ETH.sharesOf(acc)

        self.csms = {}
        self.csms_initial_balance = defaultdict(int)
        self.withdrawal_queue = None

    def add_csm(self, id: int):
        ea_accounts = OrderedSet(random.sample(chain.accounts, 10))
        ea_tree = MerkleTree()
        for acc in ea_accounts:
            ea_tree.add_leaf(keccak256(abi.encode(acc)))

        consensus_version = uint(1)
        bond_lock_retention_period = MIN_BOND_LOCK_RETENTION_PERIOD
        admin = random_account()

        module = CSModule(OssifiableProxy.deploy(
            CSModule.deploy(
                MODULE_TYPE,
                MIN_SLASHING_PENALTY_QUOTIENT,
                EL_REWARDS_STEALING_FINE,
                MAX_KEYS_PER_OPERATOR_EA,
                MAX_KEY_REMOVAL_CHARGE,
                LIDO_LOCATOR,
            ),
            admin,
            b"",
        ))
        self.csms_initial_balance[module] = module.balance
        fee_oracle = CSFeeOracle(OssifiableProxy.deploy(
            CSFeeOracle.deploy(
                SECONDS_PER_SLOT,
                GENESIS_TIME,
            ),
            admin,
            b"",
        ))
        hash_consenus = HashConsensus.deploy(
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            EPOCHS_PER_FRAME,
            FAST_LANE_LENGTH_SLOTS,
            admin,
            fee_oracle,
        )
        hash_consenus.grantRole(hash_consenus.MANAGE_MEMBERS_AND_QUORUM_ROLE(), admin, from_=admin)
        initial_epoch = timestamp_to_epoch(chain.blocks["pending"].timestamp)
        hash_consenus.updateInitialEpoch(initial_epoch, from_=admin)
        accounting = CSAccounting(OssifiableProxy.deploy(
            CSAccounting.deploy(
                LIDO_LOCATOR,
                module,
                MAX_CURVE_LENGTH,
                MIN_BOND_LOCK_RETENTION_PERIOD,
                MAX_BOND_LOCK_RETENTION_PERIOD,
            ),
            admin,
            b"",
        ))
        fee_distributor = CSFeeDistributor(OssifiableProxy.deploy(
            CSFeeDistributor.deploy(
                ST_ETH,
                accounting,
                fee_oracle,
            ),
            admin,
            b"",
        ))
        early_adoption = CSEarlyAdoption.deploy(
            ea_tree.root,
            EARLY_ADOPTION_CURVE,
            module,
        )

        # simplified beacon state:
        # | 4 x validator | 4 x withdrawal |
        dummy = bytes32(0)
        verifier = CSVerifier.deploy(
            LIDO_LOCATOR.withdrawalVault(),
            module,
            SLOTS_PER_EPOCH,
            # where to search for the first withdrawal within the state tree
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000001402"),
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000001402"),
            # where to search for the first validator within the state tree
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000001002"),
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000001002"),
            # where to search for the first historical summary within the state tree
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000300"),
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000300"),
            0,
            269568 * SLOTS_PER_EPOCH,
        )

        module.initialize(
            accounting,
            early_adoption,
            KEY_REMOVAL_CHARGE,
            admin,
        )
        module.grantRole(module.PAUSE_ROLE(), admin, from_=admin)
        module.grantRole(module.RESUME_ROLE(), admin, from_=admin)
        module.grantRole(module.REPORT_EL_REWARDS_STEALING_PENALTY_ROLE(), admin, from_=admin)
        module.grantRole(module.SETTLE_EL_REWARDS_STEALING_PENALTY_ROLE(), admin, from_=admin)
        module.grantRole(module.VERIFIER_ROLE(), verifier, from_=admin)
        module.resume(from_=admin)
        fee_oracle.initialize(
            admin,
            fee_distributor,
            hash_consenus,
            consensus_version,
            AVG_PERF_LEEWAY_BP,
        )
        fee_oracle.grantRole(fee_oracle.PAUSE_ROLE(), admin, from_=admin)
        fee_oracle.grantRole(fee_oracle.RESUME_ROLE(), admin, from_=admin)
        fee_oracle.grantRole(fee_oracle.SUBMIT_DATA_ROLE(), admin, from_=admin)

        accounting.initialize(
            CUMULATIVE_DEFAULT_BOND_CURVE,
            admin,
            fee_distributor,
            bond_lock_retention_period,
            LIDO_TREASURY,
        )
        charge_penalty_recipient = LIDO_TREASURY
        accounting.grantRole(accounting.PAUSE_ROLE(), admin, from_=admin)
        accounting.grantRole(accounting.RESUME_ROLE(), admin, from_=admin)
        accounting.grantRole(accounting.MANAGE_BOND_CURVES_ROLE(), admin, from_=admin)
        assert accounting.addBondCurve(
            CUMULATIVE_EA_BOND_CURVE,
            from_=admin,
        ).return_value == EARLY_ADOPTION_CURVE

        fee_distributor.initialize(admin)

        name, version, chain_id, verifying_contract = abi.decode(
            ST_ETH.call(abi.encode_with_signature("eip712Domain()")),
            (str, str, int, Address),
        )
        steth_domain = Eip712Domain(
            name=name,
            version=version,
            chainId=chain_id,
            verifyingContract=verifying_contract,
        )
        wsteth_domain = Eip712Domain(
            name="Wrapped liquid staked Ether 2.0",
            version="1",
            chainId=1,
            verifyingContract=WST_ETH,
        )

        for acc in [module, accounting, hash_consenus, verifier, early_adoption, fee_distributor, fee_oracle]:
            self.shares[acc] = 0

        self.burner.grantRole(self.burner.REQUEST_BURN_SHARES_ROLE(), accounting, from_="0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c")

        module.grantRole(module.MODULE_MANAGER_ROLE(), admin, from_=admin)
        module.activatePublicRelease(from_=admin)

        self.csms[id] = Csm(
            id=id,
            hash_consenus=hash_consenus,
            accounting=accounting,
            early_adoption=early_adoption,
            fee_distributor=fee_distributor,
            fee_oracle=fee_oracle,
            verifier=verifier,
            module=module,
            ea_tree=ea_tree,
            ea_accounts=ea_accounts,
            admin=admin,
            bond_lock_retention_period=bond_lock_retention_period,
            consensus_version=consensus_version,
            steth_domain=steth_domain,
            wsteth_domain=wsteth_domain,
            charge_penalty_recipient=charge_penalty_recipient,
            node_operators={},
            consensus_members=OrderedSet([]),
            initial_epoch=initial_epoch,
            consensus_quorum=0,
            last_report_ref_slot=-1,
            rewards_tree=MerkleTree(),
            queue=deque(),
            nonce=0,
            key_removal_charge=KEY_REMOVAL_CHARGE,
            total_exited_keys_count=0,
        )

        return module

    @staticmethod
    def _get_total_bond(keys_count: uint, curve: List[int]) -> uint:
        if keys_count > len(curve):
            return sum(curve) + curve[-1] * (keys_count - len(curve))
        else:
            return sum(curve[:keys_count])

    def _get_frame_info(self, csm: Csm, timestamp: uint) -> Tuple[uint, uint]:
        epoch = timestamp_to_epoch(timestamp)
        frame_start_epoch = (epoch - csm.initial_epoch) // EPOCHS_PER_FRAME * EPOCHS_PER_FRAME + csm.initial_epoch
        frame_start_slot = frame_start_epoch * SLOTS_PER_EPOCH
        next_frame_start_slot = (frame_start_epoch + EPOCHS_PER_FRAME) * SLOTS_PER_EPOCH
        return frame_start_slot - 1, next_frame_start_slot - 1

    def _get_actual_locked_bond(self, no: NodeOperator, timestamp: uint) -> uint:
        if no.lock_expiry <= timestamp:
            return 0
        return no.locked_bond

    def _get_keys_by_eth(self, no: NodeOperator, timestamp: uint, locked: bool) -> int:
        # 10 wei is added due to rounding errors in stETH shares
        available_eth = ST_ETH.getPooledEthByShares(no.bond_shares) + 10
        if locked:
            available_eth = max(available_eth - self._get_actual_locked_bond(no, timestamp), 0)

        if available_eth >= sum(no.bond_curve):
            return len(no.bond_curve) + (available_eth - sum(no.bond_curve)) // no.bond_curve[-1]
        else:
            try:
                return max(i + 1 for i, eth in enumerate(no.bond_curve) if sum(no.bond_curve[:i + 1]) <= available_eth)
            except ValueError:
                return 0

    def _get_depositable_keys(self, no: NodeOperator, timestamp: uint) -> int:
        if no.stuck_keys_count > 0:
            return 0

        keys_by_eth = self._get_keys_by_eth(no, timestamp, True)
        limit = 2**256 - 1 if no.target_limit_mode == 0 else no.target_limit

        return max(min(no.vetted_keys_count - no.deposited_keys - no.withdrawn_keys, keys_by_eth - no.deposited_keys, limit - no.deposited_keys), 0)

    def _get_enqueued_keys(self, csm: Csm, no_id: int) -> int:
        return sum(item.keys_count for item in csm.queue if item.no_id == no_id)

    def _reenqueue(self, csm: Csm, no_id: int, depositable_before: int, update_nonce: bool = False) -> None:
        depositable = self._get_depositable_keys(csm.node_operators[no_id], chain.blocks["latest"].timestamp)
        enqueued = self._get_enqueued_keys(csm, no_id)

        if depositable_before != depositable:
            assert CSModule.DepositableSigningKeysCountChanged(no_id, depositable) in chain.txs[-1].events
            if update_nonce:
                csm.nonce += 1
                assert CSModule.NonceChanged(csm.nonce) in chain.txs[-1].events
            if depositable > enqueued:
                csm.queue.append(QueueItem(
                    no_id,
                    depositable - enqueued,
                ))

            self.add_csm_depositable_keys(csm.id, depositable - depositable_before)

    @flow(max_times=(NO_AVG_COUNT * CSM_MAX_COUNT), precondition=lambda self: self.csms)
    def flow_add_no(self) -> None:
        csm = random.choice(list(self.csms.values()))

        keys_count = random_int(1, 20)
        public_keys = [random_bytes(48) for _ in range(keys_count)]
        signatures = [random_bytes(96) for _ in range(keys_count)]
        manager = random_account()
        rewards = random_account() if random.random() < 0.66 else csm.accounting
        extended_permissions = random_bool()

        sender = random_account()
        if sender in csm.ea_accounts and random.random() < 0.8:
            ea_proof = csm.ea_tree.get_proof(csm.ea_tree._leaves.index(keccak256(abi.encode(sender))))
            curve = EA_BOND_CURVE
            csm.ea_accounts.remove(sender)
        else:
            ea_proof = []
            curve = DEFAULT_BOND_CURVE
        total_bond = self._get_total_bond(keys_count, curve)
        no_id = len(csm.node_operators)

        p = random.random()
        if p < 0.33:
            # native ETH
            required_eth = csm.accounting.getBondAmountByKeysCount(
                keys_count,
                1 if curve == EA_BOND_CURVE else 0,
            )
            assert abs(required_eth - total_bond) <= 10
            total_bond = required_eth
            shares = ST_ETH.getSharesByPooledEth(total_bond)

            sender.balance += total_bond

            tx = csm.module.addNodeOperatorETH(
                keys_count,
                b"".join(public_keys),
                b"".join(signatures),
                NodeOperatorManagementProperties(
                    manager.address,
                    rewards.address,
                    extended_permissions,
                ),
                ea_proof,
                Address.ZERO,  # referrer only used for event emission
                value=total_bond,
                from_=sender,
            )
            assert CSAccounting.BondDepositedETH(no_id, sender.address, total_bond) in tx.events
            self.balances[ST_ETH] += total_bond #
        elif p < 0.66:
            # stETH
            required_eth = csm.accounting.getBondAmountByKeysCount(
                keys_count,
                1 if curve == EA_BOND_CURVE else 0,
            )
            assert abs(required_eth - total_bond) <= 10
            total_bond = required_eth
            shares = ST_ETH.getSharesByPooledEth(total_bond)

            sender.balance += total_bond
            ST_ETH.transact(from_=sender, value=total_bond)
            self.balances[ST_ETH] += total_bond # LIDO

            if random_bool():
                ST_ETH.approve(csm.accounting, total_bond, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=csm.accounting.address,
                    value=total_bond,
                    nonce=IERC20Permit(ST_ETH).nonces(sender.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, csm.steth_domain)

            tx = csm.module.addNodeOperatorStETH(
                keys_count,
                b"".join(public_keys),
                b"".join(signatures),
                NodeOperatorManagementProperties(
                    manager.address,
                    rewards.address,
                    extended_permissions,
                ),
                CSAccounting.PermitInput(
                    total_bond,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                ea_proof,
                Address.ZERO,  # referrer only used for event emission
                from_=sender,
            )
            assert CSAccounting.BondDepositedStETH(no_id, sender.address, total_bond) in tx.events
        else:
            # wstETH
            total_bond = WST_ETH.getWstETHByStETH(total_bond)

            required_wst_eth = csm.accounting.getBondAmountByKeysCountWstETH(
                keys_count,
                1 if curve == EA_BOND_CURVE else 0,
            )
            assert abs(required_wst_eth - total_bond) <= 10
            total_bond = required_wst_eth
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(total_bond))

            mint_erc20(WST_ETH, sender, total_bond)
            if random_bool():
                WST_ETH.approve(csm.accounting, total_bond, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=csm.accounting.address,
                    value=total_bond,
                    nonce=IERC20Permit(WST_ETH).nonces(sender.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, csm.wsteth_domain)

            tx = csm.module.addNodeOperatorWstETH(
                keys_count,
                b"".join(public_keys),
                b"".join(signatures),
                NodeOperatorManagementProperties(
                    manager.address,
                    rewards.address,
                    extended_permissions,
                ),
                CSAccounting.PermitInput(
                    total_bond,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                ea_proof,
                Address.ZERO,  # referrer only used for event emission
                from_=sender,
            )
            assert CSAccounting.BondDepositedWstETH(no_id, sender.address, total_bond) in tx.events



        key_infos = []
        for i in range(keys_count):
            key_infos.append(KeyInfo(public_keys[i], signatures[i], KeyState.Vetted))

        csm.node_operators[no_id] = NodeOperator(
            id=no_id,
            total_keys_count=keys_count,
            deposited_keys=0,
            vetted_keys_count=keys_count,
            withdrawn_keys=0,
            exited_keys_count=0,
            stuck_keys_count=0,
            keys_bytes=public_keys,
            signatures=signatures,
            manager=manager,
            rewards_account=rewards,
            target_limit=0,
            target_limit_mode=0,
            bond_curve=curve,
            bond_shares=shares,
            locked_bond=0,
            total_rewards=0,
            claimed_rewards=0,
            lock_expiry=0,
            slashed=defaultdict(bool),
            withdrawn=defaultdict(bool),
            keys=key_infos,
            deposited_keys_count= 0,
        )
        self.shares[csm.accounting] += shares
        csm.queue.append(QueueItem(no_id, keys_count))
        csm.nonce += 1

        if ea_proof:
            assert CSEarlyAdoption.Consumed(sender.address) in tx.events
            assert CSAccounting.BondCurveSet(no_id, 1 if ea_proof else 0) in tx.events
        else:
            assert not any(e for e in tx.events if isinstance(e, CSEarlyAdoption.Consumed))

        assert CSModule.NodeOperatorAdded(no_id, manager.address, rewards.address) in tx.events
        assert [CSModule.SigningKeyAdded(no_id, k) for k in public_keys] == [e for e in tx.events if isinstance(e, CSModule.SigningKeyAdded)]
        assert CSModule.VettedSigningKeysCountChanged(no_id, keys_count) in tx.events
        assert CSModule.TotalSigningKeysCountChanged(no_id, keys_count) in tx.events
        assert CSModule.DepositableSigningKeysCountChanged(no_id, keys_count) in tx.events
        assert CSModule.NonceChanged(csm.nonce) in tx.events

        self.add_csm_depositable_keys(csm.id, keys_count)
        self.add_csm_active_no(csm.id)
        logger.info(f"Added NO {no_id} with {keys_count} keys to CSM {csm.id}")

    @abstractmethod
    def add_csm_depositable_keys(self, id, count):
        pass

    @abstractmethod
    def add_csm_active_no(self, id):
        pass

    @flow(precondition=lambda self: self.csms)
    def flow_no_add_keys(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
        except IndexError:
            return
        no = random.choice(list(csm.node_operators.values()))
        keys_count = random_int(1, 20)
        public_keys = [random_bytes(48) for _ in range(keys_count)]
        signatures = [random_bytes(96) for _ in range(keys_count)]
        bond_increase = max(
            self._get_total_bond(no.total_keys_count - no.withdrawn_keys + keys_count, no.bond_curve) - ST_ETH.getPooledEthByShares(no.bond_shares) + self._get_actual_locked_bond(no, chain.blocks["pending"].timestamp),
            0,
        )

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        p = random.random()
        if p < 0.33:
            logger.debug("ETH used")
            required_eth = csm.accounting.getRequiredBondForNextKeys(no.id, keys_count)
            assert abs(required_eth - bond_increase) <= 10
            bond_increase = required_eth
            shares = ST_ETH.getSharesByPooledEth(bond_increase)

            # native ETH
            no.manager.balance += bond_increase

            tx = csm.module.addValidatorKeysETH(
                no.id,
                keys_count,
                b"".join(public_keys),
                b"".join(signatures),
                value=bond_increase,
                from_=no.manager,
            )
            self.balances[ST_ETH] += bond_increase # LIDO
        elif p < 0.66:
            required_eth = csm.accounting.getRequiredBondForNextKeys(no.id, keys_count)
            assert abs(required_eth - bond_increase) <= 10
            bond_increase = required_eth
            shares = ST_ETH.getSharesByPooledEth(bond_increase)
            logger.debug("stETH used")
            # stETH
            if bond_increase > 0:
                no.manager.balance += bond_increase

                # same as submit with Address(0) referral
                tx = ST_ETH.transact(from_=no.manager, value=bond_increase)

                event = next(e for e in tx.events if isinstance(e, LidoMigrated.TransferShares))
                assert event is not None
                assert event.to == no.manager.address
                assert event.sharesValue == shares

                self.balances[ST_ETH] += bond_increase

            if random_bool():
                ST_ETH.approve(csm.accounting, bond_increase, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=csm.accounting.address,
                    value=bond_increase,
                    nonce=IERC20Permit(ST_ETH).nonces(no.manager),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(permit, csm.steth_domain)

            tx = csm.module.addValidatorKeysStETH(
                no.id,
                keys_count,
                b"".join(public_keys),
                b"".join(signatures),
                CSAccounting.PermitInput(
                    bond_increase,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=no.manager,
            )
        else:
            logger.debug("wstETH used")
            # wstETH
            bond_increase = WST_ETH.getWstETHByStETH(bond_increase)
            required_wst_eth = csm.accounting.getRequiredBondForNextKeysWstETH(no.id, keys_count)
            assert abs(required_wst_eth - bond_increase) <= 10
            bond_increase = required_wst_eth
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(bond_increase))

            if bond_increase > 0:
                mint_erc20(WST_ETH, no.manager, bond_increase)

            if random_bool():
                WST_ETH.approve(csm.accounting, bond_increase, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=csm.accounting.address,
                    value=bond_increase,
                    nonce=IERC20Permit(WST_ETH).nonces(no.manager.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(permit, csm.wsteth_domain)

            tx = csm.module.addValidatorKeysWstETH(
                no.id,
                keys_count,
                b"".join(public_keys),
                b"".join(signatures),
                CSAccounting.PermitInput(
                    bond_increase,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=no.manager,
            )
        optimistic_vetting = False
        if no.total_keys_count == no.vetted_keys_count:
            # optimistic vetting
            optimistic_vetting = True
            no.vetted_keys_count += keys_count

        no.total_keys_count += keys_count
        no.bond_shares += shares
        no.keys_bytes.extend(public_keys)
        no.signatures.extend(signatures)
        if optimistic_vetting:
            no.keys.extend([KeyInfo(pkey, signature, KeyState.Vetted) for pkey, signature in zip(public_keys, signatures)])
        else:
            no.keys.extend([KeyInfo(pkey, signature, KeyState.Added) for pkey, signature in zip(public_keys, signatures)])
        self.shares[csm.accounting] += shares
        csm.nonce += 1


        self._reenqueue(csm, no.id, depositable_before)

        assert [CSModule.SigningKeyAdded(no.id, k) for k in public_keys] == [e for e in tx.events if isinstance(e, CSModule.SigningKeyAdded)]
        assert CSModule.TotalSigningKeysCountChanged(no.id, no.total_keys_count) in tx.events
        if self._get_depositable_keys(no, tx.block.timestamp) != depositable_before:
            assert CSModule.DepositableSigningKeysCountChanged(no.id, self._get_depositable_keys(no, tx.block.timestamp)) in tx.events
        assert CSModule.NonceChanged(csm.nonce) in tx.events

        logger.info(f"Added {keys_count} keys to NO {no.id} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_deposit(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
        except IndexError:
            return
        no = random.choice(list(csm.node_operators.values()))

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        p = random.random()
        if p < 0.33:
            # native ETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            no.manager.balance += amount
            shares = ST_ETH.getSharesByPooledEth(amount)

            tx = csm.module.depositETH(no.id, value=amount, from_=no.manager)
            self.balances[ST_ETH] += amount

        elif p < 0.66:
            # stETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            shares = ST_ETH.getSharesByPooledEth(amount)

            if amount > 0:
                no.manager.balance += amount
                ST_ETH.transact(from_=no.manager, value=amount)
                self.balances[ST_ETH] += amount
            if random_bool():
                ST_ETH.approve(csm.accounting, amount, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=csm.accounting.address,
                    value=amount,
                    nonce=IERC20Permit(ST_ETH).nonces(no.manager.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(permit, csm.steth_domain)

            tx = csm.module.depositStETH(
                no.id,
                amount,
                CSAccounting.PermitInput(
                    amount,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=no.manager,
            )
        else:
            # wstETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(amount))

            if amount > 0:
                mint_erc20(WST_ETH, no.manager, amount)

            if random_bool():
                WST_ETH.approve(csm.accounting, amount, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=csm.accounting.address,
                    value=amount,
                    nonce=IERC20Permit(WST_ETH).nonces(no.manager.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(permit, csm.wsteth_domain)

            tx = csm.module.depositWstETH(
                no.id,
                amount,
                CSAccounting.PermitInput(
                    amount,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=no.manager,
            )

        csm.node_operators[no.id].bond_shares += shares
        self.shares[csm.accounting] += shares

        self._reenqueue(csm, no.id, depositable_before, update_nonce=True)

        logger.info(f"Deposited {amount} to NO {no.id} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_no_remove_keys(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
            no = random.choice([no for no in csm.node_operators.values() if no.total_keys_count - no.deposited_keys - no.withdrawn_keys > 0])
        except IndexError:
            return
        keys_count = random_int(1, no.total_keys_count - no.deposited_keys - no.withdrawn_keys)
        start_index = random_int(0, no.total_keys_count - no.deposited_keys - no.withdrawn_keys - keys_count) + no.deposited_keys + no.withdrawn_keys

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = csm.module.removeKeys(no.id, start_index, keys_count, from_=no.manager)

        shares = min(ST_ETH.getSharesByPooledEth(csm.key_removal_charge * keys_count), no.bond_shares)
        no.total_keys_count -= keys_count
        prev_vetted = no.vetted_keys_count
        no.vetted_keys_count = no.total_keys_count  # optimistic removal

        for i in range(start_index, start_index + keys_count):
            assert no.keys[i].key_state == KeyState.Added or no.keys[i].key_state == KeyState.Vetted

        no.bond_shares -= shares
        self.shares[csm.accounting] -= shares
        self.shares[csm.charge_penalty_recipient] += shares
        csm.nonce += 1

        removed = []

        # queue remains as is, only keys are removed
        for i in range(keys_count, 0, -1):
            if start_index + i < len(no.keys_bytes):
                # when not removing last key, move last key to the removed position
                removed.append(no.keys_bytes[start_index + i - 1])
                no.keys_bytes[start_index + i - 1] = no.keys_bytes.pop()
                no.signatures[start_index + i - 1] = no.signatures.pop()
                no.keys[start_index + i - 1] = no.keys.pop()
            else:
                # when removing last key, just pop it
                removed.append(no.keys_bytes.pop())
                no.signatures.pop()
                no.keys.pop()


            for i in range(no.deposited_keys_count, no.vetted_keys_count): # since all of them that not deposited is vetted by optimisity
                assert no.keys[i].key_state == KeyState.Added or no.keys[i].key_state == KeyState.Vetted
                no.keys[i].key_state = KeyState.Vetted

        self._reenqueue(csm, no.id, depositable_before)

        assert [e for e in tx.events if isinstance(e, CSModule.SigningKeyRemoved)] == [
            CSModule.SigningKeyRemoved(no.id, key)
            for key in removed
        ]

        if csm.key_removal_charge * keys_count > 0:
            assert CSModule.KeyRemovalChargeApplied(no.id) in tx.events
            assert CSAccounting.BondCharged(
                no.id,
                ST_ETH.getPooledEthByShares(ST_ETH.getSharesByPooledEth(KEY_REMOVAL_CHARGE * keys_count)),
                ST_ETH.getPooledEthByShares(shares),
             ) in tx.events
        else:
            assert not any(e for e in tx.events if isinstance(e, CSModule.KeyRemovalChargeApplied))
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondCharged))

        assert CSModule.TotalSigningKeysCountChanged(no.id, no.total_keys_count) in tx.events
        assert CSModule.VettedSigningKeysCountChanged(no.id, no.vetted_keys_count) in tx.events
        assert CSModule.NonceChanged(csm.nonce) in tx.events

        logger.info(f"Removed {keys_count} keys from NO {no.id} in CSM {csm.id}")

    @abstractmethod
    def sub_csm_depositable_keys(self, id, count):
        pass


    @flow(precondition=lambda self: self.csms)
    def flow_add_consensus_member(self):
        csm = random.choice(list(self.csms.values()))
        member = random_account()
        quorum = (len(csm.consensus_members) + 1) // 2 + 1

        with may_revert(HashConsensus.DuplicateMember) as e:
            csm.hash_consenus.addMember(member, quorum, from_=csm.admin)

        if member in csm.consensus_members:
            assert e.value is not None
        else:
            assert e.value is None
            csm.consensus_members.add(member)
            csm.consensus_quorum = quorum

            logger.info(f"Added consensus member {member} with quorum {quorum} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_remove_consensus_member(self):
        csm = random.choice(list(self.csms.values()))
        member = random_account()
        quorum = (len(csm.consensus_members) - 1) // 2 + 1

        with may_revert(HashConsensus.NonMember) as e:
            csm.hash_consenus.removeMember(member, quorum, from_=csm.admin)

        if member in csm.consensus_members:
            assert e.value is None
            csm.consensus_members.remove(member)
            csm.consensus_quorum = quorum

            logger.info(f"Removed consensus member {member} with quorum {quorum} in CSM {csm.id}")
        else:
            assert e.value is not None

    @flow(precondition=lambda self: self.csms, weight=1000)
    def flow_submit_oracle_data(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if len(csm.node_operators) > 0])
        except IndexError:
            return
        ref_slot = self._get_frame_info(csm, chain.blocks["pending"].timestamp)[0]
        if ref_slot == csm.last_report_ref_slot:
            return
        if len(csm.consensus_members) == 0:
            return

        consensus_version = 1

        shares = self.shares[csm.fee_distributor] - csm.fee_distributor.totalClaimableShares()

        if shares < 0:
            return

        reports: List[CSFeeOracle.ReportData] = []
        reward_trees: List[MerkleTree] = []
        distributions: List[List[int]] = []
        node_operators: List[List[int]] = []
        # number of pre-generated reports can be adjusted but it will make harder to reach consensus
        for _ in range(2):
            # randomly distribute rewards among N node operators
            distributed = shares
            N = random_int(0, len(csm.node_operators))
            if N == 0 or distributed < N:
                distributed = 0
                distributions.append([])
                node_operators.append([])
            elif N == 1:
                no = random.choice(list(csm.node_operators.values()))
                distributions.append([distributed])
                node_operators.append([no.id])
            else:
                def custom_random_sample(start, end, k):
                    assert start > 0
                    samples = [random.randint(start, end) for _ in range(k)]
                    return sorted(samples)

                cuts = custom_random_sample(1, distributed, N - 1)
                # cuts = sorted(random.sample(range(1, distributed), N - 1))
                distribution = [cuts[0]] + [cuts[i] - cuts[i - 1] for i in range(1, N - 1)] + [distributed - cuts[-1]]
                distributions.append(distribution)
                node_operators.append(random.sample(list(csm.node_operators.keys()), N))

            rewards_tree = MerkleTree()
            for no in csm.node_operators.values():
                try:
                    index = node_operators[-1].index(no.id)
                    rewards_tree.add_leaf(keccak256(abi.encode(uint(no.id), uint(no.total_rewards + distributions[-1][index]))))
                except ValueError:
                    rewards_tree.add_leaf(keccak256(abi.encode(uint(no.id), uint(no.total_rewards))))

            # prevent empty proof issues
            if len(rewards_tree.leaves) == 1:
                rewards_tree.add_leaf(rewards_tree.leaves[0])

            reports.append(CSFeeOracle.ReportData(
                consensus_version,
                ref_slot,
                rewards_tree.root,
                random_string(32, 32),  # treeCid
                random_string(32, 32),  # logCid
                distributed,
            ))
            reward_trees.append(rewards_tree)

        votes = {
            keccak256(abi.encode(report)): OrderedSet([])
            for report in reports
        }

        # while not consensus reached
        while True:
            sender = random.choice(csm.consensus_members)

            frame_info = self._get_frame_info(csm, chain.blocks["pending"].timestamp)
            if frame_info[0] != ref_slot:
                # got into a new frame
                ref_slot = frame_info[0]
                for report in reports:
                    report.refSlot = ref_slot

                votes = {
                    keccak256(abi.encode(report)): OrderedSet([])
                    for report in reports
                }

            # sender must vote for different report if already voted
            try:
                current_report_hash = next(
                    report_hash
                    for report_hash, voters in votes.items()
                    if sender in voters
                )
                report_arr = [
                    report_hash
                    for report_hash in votes.keys()
                    if report_hash != current_report_hash
                ]
                if report_arr == []:
                    return
                report_hash = random.choice(report_arr)
            except StopIteration:
                report_hash = random.choice(list(votes.keys()))

            csm.hash_consenus.submitReport(
                ref_slot,
                report_hash,
                consensus_version,
                from_=sender,
            )

            for voters in votes.values():
                if sender in voters:
                    voters.remove(sender)
            votes[report_hash].add(sender)

            if any(len(voters) >= csm.consensus_quorum for voters in votes.values()):
                break

        report_hash = next(report_hash for report_hash, voters in votes.items() if len(voters) >= csm.consensus_quorum)
        report = next(report for report in reports if keccak256(abi.encode(report)) == report_hash)
        if report.distributed > 0:
            index = reports.index(report)
            csm.rewards_tree = reward_trees[index]

            for no, cut in zip(node_operators[index], distributions[index]):
                csm.node_operators[no].total_rewards += cut


        sender = random.choice(list(csm.consensus_members) + [csm.admin])
        tx = csm.fee_oracle.submitReportData(
            report,
            1,
            from_=sender,
        )
        csm.last_report_ref_slot = ref_slot

        assert CSFeeOracle.ProcessingStarted(ref_slot, report_hash) in tx.events
        if report.distributed > 0:
            assert CSFeeDistributor.DistributionDataUpdated(self.shares[csm.fee_distributor], report.treeRoot, report.treeCid) in tx.events
        assert CSFeeDistributor.DistributionLogUpdated(report.logCid) in tx.events

        assert csm.fee_oracle.getConsensusReport()[0] == report_hash

        logger.info(f"Submitted oracle data for ref slot {ref_slot} with {report.distributed} stETH shares distributed in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_pull_rewards(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
            no = random.choice([no for no in csm.node_operators.values() if keccak256(abi.encode(uint(no.id), uint(no.total_rewards))) in csm.rewards_tree._leaves])
        except IndexError:
            return "No rewards"

        tx = csm.accounting.pullFeeRewards(
            no.id,
            no.total_rewards,
            csm.rewards_tree.get_proof(csm.rewards_tree._leaves.index(keccak256(abi.encode(uint(no.id), uint(no.total_rewards))))),
            from_=random_account(),
        )
        claimed = no.total_rewards - no.claimed_rewards
        no.bond_shares += claimed
        no.claimed_rewards = no.total_rewards
        self.shares[csm.fee_distributor] -= claimed
        self.shares[csm.accounting] += claimed


        if claimed > 0:
            assert CSFeeDistributor.FeeDistributed(no.id, claimed) in tx.events

        logger.info(f"Pulled {claimed} stETH shares for NO {no.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_claim_rewards(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
            no = random.choice([no for no in csm.node_operators.values() if keccak256(abi.encode(uint(no.id), uint(no.total_rewards))) in csm.rewards_tree._leaves])
        except IndexError:
            return
        sender = random.choice([no.manager, no.rewards_account])
        t = chain.blocks["pending"].timestamp

        proof = csm.rewards_tree.get_proof(csm.rewards_tree._leaves.index(keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))))
        if len(proof) == 0:
            # rewards don't get pulled with empty proof
            claimable_shares = max(no.bond_shares - ST_ETH.getSharesByPooledEth(self._get_total_bond(no.total_keys_count - no.withdrawn_keys, no.bond_curve) + self._get_actual_locked_bond(no, t)), 0)
            pulled_shares = 0
        else:
            claimable_shares = max(no.bond_shares + no.total_rewards - no.claimed_rewards - ST_ETH.getSharesByPooledEth(self._get_total_bond(no.total_keys_count - no.withdrawn_keys, no.bond_curve) + self._get_actual_locked_bond(no, t)), 0)
            pulled_shares = no.total_rewards - no.claimed_rewards
        shares_to_claim = random_int(0, claimable_shares + 10, edge_values_prob=0.1)

        shares_before = ST_ETH.sharesOf(csm.accounting)
        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        p = random.random()
        with may_revert((CSAccounting.NothingToClaim, WithdrawalQueueERC721.RequestAmountTooSmall)) as ex:
            if p < 0.33:
                # unstETH
                balance_before = 0
                tx = csm.module.claimRewardsUnstETH(
                    no.id,
                    ST_ETH.getPooledEthByShares(shares_to_claim),
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                claimed_shares = shares_before + pulled_shares - ST_ETH.sharesOf(csm.accounting)


                event = next((e for e in tx.events if isinstance(e, CSAccounting.BondClaimedUnstETH)), None)

                assert event is not None
                assert event.nodeOperatorId == no.id
                assert event.to == no.rewards_account.address
                assert event.requestId == self.withdrawal_queue.getLastRequestId()

                assert abs(event.amount - ST_ETH.getPooledEthByShares(min(shares_to_claim, claimable_shares))) <= 10

            elif p < 0.66:
                # stETH
                balance_before = ST_ETH.sharesOf(no.rewards_account)
                tx = csm.module.claimRewardsStETH(
                    no.id,
                    ST_ETH.getPooledEthByShares(shares_to_claim),
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                e = [e for e in tx.raw_events if e.topics[0] == bytes.fromhex("9d9c909296d9c674451c0c24f02cb64981eb3b727f99865939192f880a755dcb")][-1]
                claimed_shares = abi.decode(e.data, [uint])

                assert CSAccounting.BondClaimedStETH(no.id, no.rewards_account.address, ST_ETH.getPooledEthByShares(claimed_shares)) in tx.events
            else:
                # wstETH
                balance_before = WST_ETH.balanceOf(no.rewards_account)
                tx = csm.module.claimRewardsWstETH(
                    no.id,
                    shares_to_claim,
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                claimed_shares = shares_before + pulled_shares - ST_ETH.sharesOf(csm.accounting)

                assert CSAccounting.BondClaimedWstETH(no.id, no.rewards_account.address, claimed_shares) in tx.events

        if isinstance(ex.value, CSAccounting.NothingToClaim):
            assert min(shares_to_claim, claimable_shares) == 0 or p < 0.66 and ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(shares_to_claim)) == 0
            return "Nothing to claim"
        elif isinstance(ex.value, WithdrawalQueueERC721.RequestAmountTooSmall):
            assert p < 0.33 and (
                ST_ETH.getPooledEthByShares(
                    ST_ETH.getSharesByPooledEth(
                        ST_ETH.getPooledEthByShares(min(shares_to_claim, claimable_shares))
                    )
                )
             ) < 100
            return "Request amount too small"
        assert ex.value is None

        # pull part
        if len(proof) != 0:
            no.bond_shares += pulled_shares
            no.claimed_rewards = no.total_rewards
            self.shares[csm.fee_distributor] -= pulled_shares
            self.shares[csm.accounting] += pulled_shares

            if pulled_shares > 0:
                assert CSFeeDistributor.FeeDistributed(no.id, pulled_shares) in tx.events

        # claim part
        print(f"error: {claimed_shares - shares_to_claim}")
        assert claimed_shares <= min(shares_to_claim, claimable_shares)
        assert abs(claimed_shares - shares_to_claim) <= 11
        no.bond_shares -= claimed_shares

        self.shares[csm.accounting] -= claimed_shares
        if p < 0.33:
            last_withdrawal_id = self.withdrawal_queue.getLastRequestId()
            assert self.withdrawal_queue.getWithdrawalStatus([last_withdrawal_id])[0].amountOfShares == claimed_shares
        elif p < 0.66:
            if no.rewards_account != csm.accounting:
                assert ST_ETH.sharesOf(no.rewards_account) == balance_before + claimed_shares
            else:
                assert ST_ETH.sharesOf(no.rewards_account) == balance_before + pulled_shares
            self.shares[no.rewards_account] += claimed_shares
        else:
            assert WST_ETH.balanceOf(no.rewards_account) == balance_before + claimed_shares

        self._reenqueue(csm, no.id, depositable_before, update_nonce=True)

        logger.info(f"Claimed {claimed_shares} stETH shares for NO {no.id} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_report_stealing(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
        except IndexError:
            return
        no = random.choice(list(csm.node_operators.values()))
        amount = random_int(0, Wei.from_ether(3), edge_values_prob=0.1)
        block_hash = random_bytes(32)

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount
        with may_revert(CSModule.InvalidAmount) as e:
            tx = csm.module.reportELRewardsStealingPenalty(
                no.id,
                block_hash,
                amount,
                from_=csm.admin,
            )

        if e.value is not None:
            assert amount == 0
            return "Invalid amount"
        else:
            assert amount > 0

        if no.lock_expiry <= tx.block.timestamp:
            no.locked_bond = amount + EL_REWARDS_STEALING_FINE
        else:
            no.locked_bond += amount + EL_REWARDS_STEALING_FINE
        no.lock_expiry = tx.block.timestamp + csm.bond_lock_retention_period

        depositable = self._get_depositable_keys(csm.node_operators[no.id], chain.blocks["latest"].timestamp)

        self._reenqueue(csm, no.id, depositable_before, update_nonce=True)

        assert CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry) in tx.events
        assert CSModule.ELRewardsStealingPenaltyReported(no.id, block_hash, amount) in tx.events

        logger.info(f"Reported {amount} wei stealing penalty for NO {no.id} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_cancel_stealing_penalty(self):
        t = chain.blocks["pending"].timestamp
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
            no = random.choice([no for no in csm.node_operators.values() if self._get_actual_locked_bond(no, t)])
        except IndexError:
            return
        locked = self._get_actual_locked_bond(no, t)
        amount = random_int(1, self._get_actual_locked_bond(no, t), edge_values_prob=0.2)

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = csm.module.cancelELRewardsStealingPenalty(
            no.id,
            amount,
            from_=csm.admin,
        )

        no.locked_bond -= amount
        if no.locked_bond == 0:
            no.lock_expiry = 0

        self._reenqueue(csm, no.id, depositable_before, update_nonce=True)

        if amount == locked:
            assert CSAccounting.BondLockRemoved(no.id) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockChanged))
        else:
            assert CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockRemoved))
        assert CSModule.ELRewardsStealingPenaltyCancelled(no.id, amount) in tx.events

        logger.info(f"Canceled {amount} wei stealing penalty for NO {no.id} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_settle_stealing_penalty(self):
        csm = random.choice(list(self.csms.values()))
        depositable_before = {no.id: csm.module.getNodeOperator(no.id).depositableValidatorsCount for no in csm.node_operators.values()}
        tx = csm.module.settleELRewardsStealingPenalty(list(csm.node_operators.keys()), from_=csm.admin)

        for no in csm.node_operators.values():
            if self._get_actual_locked_bond(no, tx.block.timestamp) > 0:
                shares = ST_ETH.getSharesByPooledEth(no.locked_bond)
                no.bond_curve = DEFAULT_BOND_CURVE
                assert csm.accounting.getBondCurveId(no.id) == 0

                shares = min(shares, no.bond_shares)
                self.shares[csm.accounting] -= shares
                self.shares[self.burner] += shares
                no.bond_shares -= shares
                no.locked_bond = 0
                no.lock_expiry = 0

                self._reenqueue(csm, no.id, depositable_before[no.id], update_nonce=True)


                assert CSAccounting.BondLockRemoved(no.id) in tx.events
                assert CSModule.ELRewardsStealingPenaltySettled(no.id) in tx.events
            else:
                assert CSAccounting.BondLockRemoved(no.id) not in tx.events
                assert CSModule.ELRewardsStealingPenaltySettled(no.id) not in tx.events

        logger.info(f"Settled stealing penalties in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_compensate_stealing_penalty(self):
        t = chain.blocks["pending"].timestamp
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
            no = random.choice([no for no in csm.node_operators.values() if self._get_actual_locked_bond(no, t) > 0])
        except IndexError:
            return "No NO with locked bond"
        locked = self._get_actual_locked_bond(no, t)
        amount = random_int(1, locked, edge_values_prob=0.2)
        no.manager.balance += amount

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = csm.module.compensateELRewardsStealingPenalty(no.id, value=amount, from_=no.manager)

        no.locked_bond -= amount
        self.balances[self.el_rewards_vault] += amount
        if no.locked_bond == 0:
            no.lock_expiry = 0

        self._reenqueue(csm, no.id, depositable_before, update_nonce=True)
        if amount == locked:
            assert CSAccounting.BondLockRemoved(no.id) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockChanged))
        else:
            assert CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockRemoved))

        assert CSAccounting.BondLockCompensated(no.id, amount) in tx.events

        logger.info(f"Compensated {amount} wei stealing penalty for NO {no.id} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_normalize_queue(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
        except IndexError:
            return
        no = random.choice(list(csm.node_operators.values()))

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount
        tx = csm.module.normalizeQueue(no.id, from_=no.manager)

        # contract sees different number of depositable keys than we do
        depositable = csm.module.getNodeOperator(no.id).depositableValidatorsCount
        enqueued = self._get_enqueued_keys(csm, no.id)
        if enqueued < depositable:
            csm.queue.append(QueueItem(no.id, depositable - enqueued))

        depositable = self._get_depositable_keys(csm.node_operators[no.id], chain.blocks["latest"].timestamp)

        self.add_csm_depositable_keys(csm.id, depositable - depositable_before)
        if depositable != depositable_before:
            csm.nonce += 1
            assert CSModule.DepositableSigningKeysCountChanged(no.id, depositable) in tx.events
            assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Normalized queue for NO {no.id} in CSM {csm.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_clean_deposit_queue(self):
        csm = random.choice(list(self.csms.values()))
        depositable_keys = {
            no.id: csm.module.getNodeOperator(no.id).depositableValidatorsCount
            for no in csm.node_operators.values()
        }
        max_items = random_int(1, max(len(csm.queue), 1))

        tx = csm.module.cleanDepositQueue(max_items, from_=random_account())

        enqueued_keys = defaultdict(int)

        new_queue = deque()
        removed_items = 0
        last_removal_pos = 0

        for i, item in enumerate(csm.queue):
            if i >= max_items:
                new_queue.append(item)
                continue

            if depositable_keys[item.no_id] > enqueued_keys[item.no_id]:
                enqueued_keys[item.no_id] += item.keys_count
                new_queue.append(item)
            else:
                removed_items += 1
                last_removal_pos = i + 1

        csm.queue = new_queue
        assert tx.return_value == (removed_items, last_removal_pos)

        logger.info(f"Cleaned deposit queue in CSM {csm.id}")

    @flow()
    def flow_process_historical_withdrawal_proof(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
            no = random.choice([no for no in csm.node_operators.values() if no.deposited_keys + no.withdrawn_keys > 0])
        except IndexError:
            return "No NO with deposited keys"
        index = random_int(0, no.deposited_keys + no.withdrawn_keys - 1)
        slashed = random_bool() or no.slashed[index]
        amount = random_int(1, (Wei.from_ether(32) if not slashed else Wei.from_ether(31)) // 10 ** 9, max_prob=0.2)

        slot = timestamp_to_slot(chain.blocks["latest"].timestamp)

        validator = Validator(
            no.keys_bytes[index],
            b"\x01" + 11 * b"\x00" + bytes(LIDO_LOCATOR.withdrawalVault()),
            random_int(0, 2**64 - 1),
            slashed,
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, slot // SLOTS_PER_EPOCH),
        )
        validator_root = hash_validator(validator)

        old_state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        validator_leaves = [
            validator_root,
            random_bytes(32),
            random_bytes(32),
            random_bytes(32),
        ]
        random.shuffle(validator_leaves)
        validator_index = validator_leaves.index(validator_root)

        for leaf in validator_leaves:
            old_state_tree.add_leaf(leaf)

        withdrawal = Withdrawal(
            random_int(0, 2**64 - 1),
            validator_index,
            LIDO_LOCATOR.withdrawalVault(),
            amount,
        )
        withdrawal_root = hash_withdrawal(withdrawal)
        withdrawal_leaves = [
            withdrawal_root,
            random_bytes(32),
            random_bytes(32),
            random_bytes(32),
        ]
        random.shuffle(withdrawal_leaves)
        withdrawal_offset = withdrawal_leaves.index(withdrawal_root)

        for leaf in withdrawal_leaves:
            old_state_tree.add_leaf(leaf)

        # historical summaries in old block
        for _ in range(8):
            old_state_tree.add_leaf(random_bytes(32))

        witness = CSVerifier.WithdrawalWitness(
            withdrawal_offset,
            withdrawal.index,
            validator_index,
            amount,
            validator.withdrawalCredentials,
            validator.effectiveBalance,
            validator.slashed,
            validator.activationEligibilityEpoch,
            validator.activationEpoch,
            validator.exitEpoch,
            validator.withdrawableEpoch,
            old_state_tree.get_proof(old_state_tree.leaves.index(withdrawal_root)),
            old_state_tree.get_proof(old_state_tree.leaves.index(validator_root)),
        )

        old_block_header = BeaconBlockHeader(
            slot,
            random_int(0, 2**64 - 1),
            random_bytes(32),
            old_state_tree.root,
            random_bytes(32),
        )

        state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)

        # validators + withdrawals
        for _ in range(8):
            state_tree.add_leaf(random_bytes(32))

        historical_summary = hash_beacon_block_header(old_block_header)
        historical_summary_leaves = [historical_summary] + [random_bytes(32) for _ in range(7)]
        random.shuffle(historical_summary_leaves)
        historical_summary_offset = historical_summary_leaves.index(historical_summary)

        for leaf in historical_summary_leaves:
            state_tree.add_leaf(leaf)

        block_header = BeaconBlockHeader(
            slot,
            random_int(0, 2**64 - 1),
            random_bytes(32),
            state_tree.root,
            random_bytes(32),
        )

        root = hash_beacon_block_header(block_header)
        tx = Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").transact(root, from_="0xfffffffffffffffffffffffffffffffffffffffe")
        assert Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").call(tx.block.timestamp.to_bytes(32, "big")) == root

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert((CSModule.AlreadySubmitted, CSVerifier.PartialWithdrawal)) as e:
            tx = csm.verifier.processHistoricalWithdrawalProof(
                CSVerifier.ProvableBeaconBlockHeader(
                    block_header,
                    tx.block.timestamp,
                ),
                CSVerifier.HistoricalHeaderWitness(
                    old_block_header,
                    (0x18 + historical_summary_offset).to_bytes(31, "big") + b"\03",
                    state_tree.get_proof(state_tree.leaves.index(historical_summary)),
                ),
                witness,
                no.id,
                index,
                from_=random_account(),
            )

        if not slashed and amount * 10 ** 9 < Wei.from_ether(8):
            assert e.value == CSVerifier.PartialWithdrawal()
            return "Partial withdrawal"
        elif no.withdrawn[index]:
            assert e.value == CSModule.AlreadySubmitted()
            return "Already submitted"

        assert e.value is None
        assert CSModule.WithdrawalSubmitted(no.id, index, amount * 10 ** 9, no.keys[index].pkey) in tx.events

        no.deposited_keys -= 1
        no.withdrawn_keys += 1

        max_amount = (Wei.from_ether(31) if no.slashed[index] else Wei.from_ether(32)) // 10 ** 9  # if previously slashed, don't slash again; in gwei
        if amount < max_amount:
            # steth burned
            shares = min(ST_ETH.getSharesByPooledEth((max_amount - amount) * 10 ** 9), no.bond_shares)
            self.shares[csm.accounting] -= shares
            self.shares[self.burner] += shares
            no.bond_shares -= shares

            burned = ST_ETH.getPooledEthByShares(shares)
            if burned > 0:
                assert CSAccounting.BondBurned(
                    no.id,
                    ST_ETH.getPooledEthByShares(ST_ETH.getSharesByPooledEth((max_amount - amount) * 10 ** 9)),
                    burned,
                ) in tx.events
        else:
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondBurned))

        no.slashed[index] = slashed
        no.withdrawn[index] = True

        if slashed:
            no.bond_curve = DEFAULT_BOND_CURVE

        self._reenqueue(csm, no.id, depositable_before, update_nonce=True)

        logger.info(f"Processed historical withdrawal proof for NO {no.id}")

    @flow()
    def flow_process_withdrawal_proof(self):
        try:
            csm = random.choice([csm for csm in self.csms.values() if csm.node_operators])
            no = random.choice([no for no in csm.node_operators.values() if no.deposited_keys + no.withdrawn_keys > 0])
        except IndexError:
            return "No NO with deposited keys"
        index = random_int(0, no.deposited_keys + no.withdrawn_keys - 1)

        self._withdraw(csm, no, index)

    def _withdraw(self, csm: Csm, no: NodeOperator, index: int, update_state: bool = True, full_withdraw: bool = False):
        if not update_state:
            slashed = False or no.slashed[index]
        else:
            slashed = random_bool() or no.slashed[index]

        if full_withdraw:
            amount = (Wei.from_ether(32) if not slashed else Wei.from_ether(31)) // 10 ** 9
        else:
            amount = random_int(1, (Wei.from_ether(32) if not slashed else Wei.from_ether(31)) // 10 ** 9, max_prob=0.2)

        slot = timestamp_to_slot(chain.blocks["latest"].timestamp)

        validator = Validator(
            no.keys[index].pkey,
            b"\x01" + 11 * b"\x00" + bytes(LIDO_LOCATOR.withdrawalVault()),
            random_int(0, 2**64 - 1),
            slashed,
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, 2**64 - 1),
            random_int(0, slot // SLOTS_PER_EPOCH),
        )
        validator_root = hash_validator(validator)

        state_tree = MerkleTree("sha256", hash_leaves=False, sort_pairs=False)
        validator_leaves = [
            validator_root,
            random_bytes(32),
            random_bytes(32),
            random_bytes(32),
        ]
        random.shuffle(validator_leaves)
        validator_index = validator_leaves.index(validator_root)

        for leaf in validator_leaves:
            state_tree.add_leaf(leaf)

        withdrawal = Withdrawal(
            random_int(0, 2**64 - 1),
            validator_index,
            LIDO_LOCATOR.withdrawalVault(),
            amount,
        )
        withdrawal_root = hash_withdrawal(withdrawal)
        withdrawal_leaves = [
            withdrawal_root,
            random_bytes(32),
            random_bytes(32),
            random_bytes(32),
        ]
        random.shuffle(withdrawal_leaves)
        withdrawal_offset = withdrawal_leaves.index(withdrawal_root)

        for leaf in withdrawal_leaves:
            state_tree.add_leaf(leaf)

        for _ in range(8):
            state_tree.add_leaf(random_bytes(32))

        witness = CSVerifier.WithdrawalWitness(
            withdrawal_offset,
            withdrawal.index,
            validator_index,
            amount,
            validator.withdrawalCredentials,
            validator.effectiveBalance,
            validator.slashed,
            validator.activationEligibilityEpoch,
            validator.activationEpoch,
            validator.exitEpoch,
            validator.withdrawableEpoch,
            state_tree.get_proof(state_tree.leaves.index(withdrawal_root)),
            state_tree.get_proof(state_tree.leaves.index(validator_root)),
        )

        block_header = BeaconBlockHeader(
            slot,
            random_int(0, 2**64 - 1),
            random_bytes(32),
            state_tree.root,
            random_bytes(32),
        )

        root = hash_beacon_block_header(block_header)
        tx = Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").transact(root, from_="0xfffffffffffffffffffffffffffffffffffffffe")
        assert Account("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02").call(tx.block.timestamp.to_bytes(32, "big")) == root

        depositable_before = csm.module.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert((CSModule.AlreadySubmitted, CSVerifier.PartialWithdrawal)) as e:
            tx = csm.verifier.processWithdrawalProof(
                CSVerifier.ProvableBeaconBlockHeader(
                    block_header,
                    tx.block.timestamp,
                ),
                witness,
                no.id,
                index,
                from_=random_account(),
            )

        if not slashed and amount * 10 ** 9 < Wei.from_ether(8):
            assert e.value == CSVerifier.PartialWithdrawal()
            return "Partial withdrawal"
        elif no.withdrawn[index]:
            assert e.value == CSModule.AlreadySubmitted()
            return "Already submitted"

        assert e.value is None
        assert CSModule.WithdrawalSubmitted(no.id, index, amount * 10 ** 9, no.keys[index].pkey) in tx.events

        if not update_state:
            return

        no.deposited_keys -= 1
        no.withdrawn_keys += 1

        max_amount = (Wei.from_ether(31) if no.slashed[index] else Wei.from_ether(32)) // 10 ** 9  # if previously slashed, don't slash again; in gwei
        if amount < max_amount:
            # steth burned
            shares = min(ST_ETH.getSharesByPooledEth((max_amount - amount) * 10 ** 9), no.bond_shares)
            self.shares[csm.accounting] -= shares
            self.shares[self.burner] += shares
            no.bond_shares -= shares

            burned = ST_ETH.getPooledEthByShares(shares)
            if burned > 0:
                assert CSAccounting.BondBurned(
                    no.id,
                    ST_ETH.getPooledEthByShares(ST_ETH.getSharesByPooledEth((max_amount - amount) * 10 ** 9)),
                    burned,
                ) in tx.events
        else:
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondBurned))

        no.slashed[index] = slashed
        no.withdrawn[index] = True

        if slashed:
            no.bond_curve = DEFAULT_BOND_CURVE

        self._reenqueue(csm, no.id, depositable_before, update_nonce=True)

        logger.info(f"Processed withdrawal proof for NO {no.id}")

    @flow(precondition=lambda self: self.csms)
    def flow_set_key_removal_charge(self):
        csm = random.choice(list(self.csms.values()))

        tx = csm.module.setKeyRemovalCharge(KEY_REMOVAL_CHARGE, from_=csm.admin)

        csm.key_removal_charge = KEY_REMOVAL_CHARGE

        logger.info(f"Set key removal charge to {KEY_REMOVAL_CHARGE} in CSM {csm.id}")

    def make_zero_removal_charge(self, csm_id: int): # used from test_fuzz when withdrawal_credential_change
        self.csms[csm_id].key_removal_charge = 0

    @flow(precondition=lambda self: self.csms)
    def flow_transfer_steth(self):
        csm = random.choice(list(self.csms.values()))
        amount = random_int(1, Wei.from_ether(1))
        acc = random_account()
        acc.balance += amount

        shares = ILido(ST_ETH).submit(Address.ZERO, from_=acc, value=amount).return_value

        ST_ETH.transferShares(csm.accounting, shares, from_=acc)

        self.balances[ST_ETH] += amount

        self.shares[csm.accounting] += shares

        logger.info(f"Transferred {shares} to accounting")

    @flow(precondition=lambda self: self.csms)
    def flow_transfer_wst_eth(self):
        csm = random.choice(list(self.csms.values()))
        amount = random_int(1, 10000)
        mint_erc20(WST_ETH, csm.accounting, amount)

        logger.info(f"Transferred {amount} wstETH to accounting")

    # @flow()
    # def flow_steth_submit(self):
    #     amount = random_int(1, 10000)
    #     acc = random_account(chain=chain)
    #     acc.balance += amount
    #     tx = ILido(ST_ETH).submit(Address.ZERO, from_=acc, value=amount)
    #     self.shares[acc] += tx.return_value
    #     t = tx.block.timestamp
    #     for no in self.node_operators.values():
    #         unbonded = no.total_keys - no.withdrawn_keys - self._get_keys_by_eth(no, t, False)
    #         assert self.accounting.getUnbondedKeysCountToEject(no.id) == max(unbonded, 0)
    #         assert self.accounting.getUnbondedKeysCount(no.id) == max(no.total_keys - no.withdrawn_keys - self._get_keys_by_eth(no, t, True), 0)

    def on_obtain_deposit_data(self, csm_id: int, depositable_keys: Dict[int, uint32], tx: TransactionAbc):
        csm = self.csms[csm_id]

        deposits_per_no = defaultdict(int)
        for e in tx.events:
            if isinstance(e, CSModule.DepositedSigningKeysCountChanged):
                deposits_per_no[e.nodeOperatorId] = e.depositedKeysCount

        deposits_count = sum(
            deposits -
            csm.node_operators[no].deposited_keys -
            csm.node_operators[no].withdrawn_keys
            for no, deposits in deposits_per_no.items()
        )

        keys = bytearray(b"")
        signatures = bytearray(b"")
        deposited = 0

        while deposits_count > deposited:
            item = csm.queue[0]
            no = csm.node_operators[item.no_id]
            keys_count = min(
                item.keys_count,
                deposits_count - deposited,
                depositable_keys[item.no_id],
            )

            keys += b"".join(no.keys_bytes[no.deposited_keys + no.withdrawn_keys:no.deposited_keys + no.withdrawn_keys + keys_count])
            signatures += b"".join(no.signatures[no.deposited_keys + no.withdrawn_keys:no.deposited_keys + no.withdrawn_keys + keys_count])


            for i in range(no.deposited_keys + no.withdrawn_keys, no.deposited_keys + no.withdrawn_keys + keys_count):
                assert no.keys[i].key_state == KeyState.Vetted
                no.keys[i].key_state = KeyState.Deposited

            if item.keys_count == keys_count:
                # consume the whole item
                csm.queue.popleft()
                no.deposited_keys += keys_count
                no.deposited_keys_count += keys_count
            else:
                # consume part of the item
                item.keys_count -= keys_count
                no.deposited_keys += keys_count
                no.deposited_keys_count += keys_count
                if deposited + keys_count != deposits_count:
                    # the rest of the keys of the given validator are not depositable, consume the whole item
                    csm.queue.popleft()

            deposited += keys_count
            depositable_keys[item.no_id] -= keys_count

        if deposited != 0:
            assert CSModule.DepositedSigningKeysCountChanged(no.id, no.deposited_keys + no.withdrawn_keys) in tx.events
            assert CSModule.DepositableSigningKeysCountChanged(no.id, depositable_keys[item.no_id]) in tx.events
            csm.nonce += 1

        self.add_deposited_keys(csm_id, deposited)
        self.sub_csm_depositable_keys(csm_id, deposited)
        self.add_csm_beacon_deposited_keys(deposited)

        deposits = [e for e in tx.events if isinstance(e, IDepositContract.DepositEvent)]

        assert len(keys) // 48 == len(deposits)
        assert len(signatures) // 96 == len(deposits)

        for i, e in enumerate(deposits):
            assert e.pubkey == keys[i * 48:i * 48 + 48]
            assert e.signature == signatures[i * 96:i * 96 + 96]

        self.balances[ST_ETH] -= deposits_count * 32 * 10**18
        logger.info(f"Obtained deposit data for {deposits_count} keys")

    @abstractmethod
    def add_deposited_keys(self, id, count):
        pass

    @abstractmethod
    def add_csm_beacon_deposited_keys(self, count):
        pass
