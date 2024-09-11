import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Tuple
from ordered_set import OrderedSet
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.csm.src.CSAccounting import CSAccounting
from pytypes.csm.src.CSEarlyAdoption import CSEarlyAdoption
from pytypes.csm.src.CSFeeDistributor import CSFeeDistributor
from pytypes.csm.src.CSFeeOracle import CSFeeOracle
from pytypes.csm.src.CSVerifier import CSVerifier
from pytypes.csm.src.CSModule import CSModule
from pytypes.csm.src.lib.baseoracle.HashConsensus import HashConsensus
from pytypes.csm.src.lib.proxy.OssifiableProxy import OssifiableProxy
from pytypes.csm.src.lib.NOAddresses import NOAddresses
from pytypes.csm.src.lib.AssetRecovererLib import AssetRecovererLib
from pytypes.csm.src.lib.QueueLib import QueueLib
from pytypes.csm.src.lib.Types import BeaconBlockHeader, Withdrawal, Validator
from pytypes.csm.src.interfaces.IStETH import IStETH
from pytypes.csm.src.interfaces.IWstETH import IWstETH
from pytypes.csm.src.interfaces.ILido import ILido
from pytypes.csm.src.interfaces.ILidoLocator import ILidoLocator
from pytypes.csm.src.interfaces.ICSModule import NodeOperatorManagementProperties
from pytypes.csm.src.interfaces.IBurner import IBurner
from pytypes.csm.src.interfaces.IWithdrawalQueue import IWithdrawalQueue
from pytypes.tests.IEIP712 import IEIP712
from pytypes.core.contracts._089.WithdrawalQueueERC721 import WithdrawalQueueERC721 as IUnstETH
from pytypes.csm.node_modules.openzeppelin.contracts.token.ERC20.extensions.IERC20Permit import IERC20Permit

from .merkle_tree import MerkleTree

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


DEFAULT_CURVE = uint(0)
EARLY_ADOPTION_CURVE = uint(1)
ST_ETH = IStETH("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
WST_ETH = IWstETH("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0")
UNST_ETH = IWithdrawalQueue("0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1")
SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12
EPOCHS_PER_FRAME = 225 * 28  # 28 days
GENESIS_TIME = 1606824023
MODULE_TYPE = random_bytes(32)

LIDO_LOCATOR = ILidoLocator("0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb")
LIDO_TREASURY = Account("0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c")
STAKING_ROUTER: Account
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
    total_keys: int
    deposited_keys: int
    vetted_keys: int
    withdrawn_keys: int
    exited_keys: int
    stuck_keys: int
    keys: List[bytes]
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


@dataclass
class QueueItem:
    no_id: int
    keys_count: int


def timestamp_to_slot(timestamp: uint) -> uint:
    return (timestamp - GENESIS_TIME) // SECONDS_PER_SLOT


def slot_to_timestamp(slot: uint) -> uint:
    return slot * SECONDS_PER_SLOT + GENESIS_TIME


def timestamp_to_epoch(timestamp: uint) -> uint:
    return timestamp_to_slot(timestamp) // SLOTS_PER_EPOCH


class CsmFuzzTest(FuzzTest):
    hash_consenus: HashConsensus
    accounting: CSAccounting
    early_adoption: CSEarlyAdoption
    fee_distributor: CSFeeDistributor
    fee_oracle: CSFeeOracle
    verifier: CSVerifier
    module: CSModule
    burner: IBurner
    el_rewards_vault: Account

    ea_tree: MerkleTree
    ea_accounts: OrderedSet[Account]
    admin: Account
    bond_lock_retention_period: uint
    consensus_version: uint
    steth_domain: Eip712Domain
    wsteth_domain: Eip712Domain
    charge_penalty_recipient: Account

    node_operators: Dict[int, NodeOperator]
    balances: Dict[Account, uint]
    shares: Dict[Account, uint]
    consensus_members: OrderedSet[Account]
    initial_epoch: int
    consensus_quorum: int
    last_report_ref_slot: int
    rewards_tree: MerkleTree
    queue: deque[QueueItem]
    nonce: uint

    def pre_sequence(self) -> None:
        global STAKING_ROUTER
        STAKING_ROUTER = Account(LIDO_LOCATOR.stakingRouter())
        self.burner = IBurner(LIDO_LOCATOR.burner())
        self.el_rewards_vault = Account(LIDO_LOCATOR.elRewardsVault())

        NOAddresses.deploy()
        AssetRecovererLib.deploy()
        QueueLib.deploy()

        self.ea_accounts = OrderedSet(random.sample(chain.accounts, 10))
        self.ea_tree = MerkleTree()
        for acc in self.ea_accounts:
            self.ea_tree.add_leaf(keccak256(abi.encode(acc)))
        self.node_operators = {}
        self.balances = defaultdict(int)
        self.shares = defaultdict(int)
        for acc in [LIDO_TREASURY, self.burner, self.el_rewards_vault] + list(chain.accounts):
            self.balances[acc] = acc.balance
            self.shares[acc] = ST_ETH.sharesOf(acc)
        self.consensus_members = OrderedSet([])
        self.consensus_quorum = 0
        self.last_report_ref_slot = -1
        self.rewards_tree = MerkleTree()
        self.queue = deque()
        self.nonce = 0

        self.consensus_version = uint(1)
        self.bond_lock_retention_period = MIN_BOND_LOCK_RETENTION_PERIOD
        self.admin = random_account()

        self.module = CSModule(OssifiableProxy.deploy(
            CSModule.deploy(
                MODULE_TYPE,
                MIN_SLASHING_PENALTY_QUOTIENT,
                EL_REWARDS_STEALING_FINE,
                MAX_KEYS_PER_OPERATOR_EA,
                MAX_KEY_REMOVAL_CHARGE,
                LIDO_LOCATOR,
            ),
            self.admin,
            b"",
        ))
        self.fee_oracle = CSFeeOracle(OssifiableProxy.deploy(
            CSFeeOracle.deploy(
                SECONDS_PER_SLOT,
                GENESIS_TIME,
            ),
            self.admin,
            b"",
        ))
        self.hash_consenus = HashConsensus.deploy(
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            EPOCHS_PER_FRAME,
            FAST_LANE_LENGTH_SLOTS,
            self.admin,
            self.fee_oracle,
        )
        self.hash_consenus.grantRole(self.hash_consenus.MANAGE_MEMBERS_AND_QUORUM_ROLE(), self.admin, from_=self.admin)
        self.initial_epoch = timestamp_to_epoch(chain.blocks["pending"].timestamp)
        self.hash_consenus.updateInitialEpoch(self.initial_epoch, from_=self.admin)
        self.accounting = CSAccounting(OssifiableProxy.deploy(
            CSAccounting.deploy(
                LIDO_LOCATOR,
                self.module,
                MAX_CURVE_LENGTH,
                MIN_BOND_LOCK_RETENTION_PERIOD,
                MAX_BOND_LOCK_RETENTION_PERIOD,
            ),
            self.admin,
            b"",
        ))
        self.fee_distributor = CSFeeDistributor(OssifiableProxy.deploy(
            CSFeeDistributor.deploy(
                ST_ETH,
                self.accounting,
                self.fee_oracle,
            ),
            self.admin,
            b"",
        ))
        self.early_adoption = CSEarlyAdoption.deploy(
            self.ea_tree.root,
            EARLY_ADOPTION_CURVE,
            self.module,
        )

        # simplified beacon state:
        # | 4 x validator | 4 x withdrawal |
        self.verifier = CSVerifier.deploy(
            LIDO_LOCATOR.withdrawalVault(),
            self.module,
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

        self.module.initialize(
            self.accounting,
            self.early_adoption,
            KEY_REMOVAL_CHARGE,
            self.admin,
        )
        self.module.grantRole(self.module.PAUSE_ROLE(), self.admin, from_=self.admin)
        self.module.grantRole(self.module.RESUME_ROLE(), self.admin, from_=self.admin)
        self.module.grantRole(self.module.REPORT_EL_REWARDS_STEALING_PENALTY_ROLE(), self.admin, from_=self.admin)
        self.module.grantRole(self.module.SETTLE_EL_REWARDS_STEALING_PENALTY_ROLE(), self.admin, from_=self.admin)
        self.module.grantRole(self.module.VERIFIER_ROLE(), self.verifier, from_=self.admin)
        self.module.resume(from_=self.admin)
        self.fee_oracle.initialize(
            self.admin,
            self.fee_distributor,
            self.hash_consenus,
            self.consensus_version,
            AVG_PERF_LEEWAY_BP,
        )
        self.fee_oracle.grantRole(self.fee_oracle.PAUSE_ROLE(), self.admin, from_=self.admin)
        self.fee_oracle.grantRole(self.fee_oracle.RESUME_ROLE(), self.admin, from_=self.admin)
        self.fee_oracle.grantRole(self.fee_oracle.SUBMIT_DATA_ROLE(), self.admin, from_=self.admin)

        self.accounting.initialize(
            CUMULATIVE_DEFAULT_BOND_CURVE,
            self.admin,
            self.fee_distributor,
            self.bond_lock_retention_period,
            LIDO_TREASURY,
        )
        self.charge_penalty_recipient = LIDO_TREASURY
        self.accounting.grantRole(self.accounting.PAUSE_ROLE(), self.admin, from_=self.admin)
        self.accounting.grantRole(self.accounting.RESUME_ROLE(), self.admin, from_=self.admin)
        self.accounting.grantRole(self.accounting.MANAGE_BOND_CURVES_ROLE(), self.admin, from_=self.admin)
        assert self.accounting.addBondCurve(
            CUMULATIVE_EA_BOND_CURVE,
            from_=self.admin,
        ).return_value == EARLY_ADOPTION_CURVE

        self.fee_distributor.initialize(self.admin)

        domain = IEIP712(ST_ETH).eip712Domain()
        self.steth_domain = Eip712Domain(
            name=domain[0],
            version=domain[1],
            chainId=domain[2],
            verifyingContract=domain[3],
        )
        self.wsteth_domain = Eip712Domain(
            name="Wrapped liquid staked Ether 2.0",
            version="1",
            chainId=1,
            verifyingContract=WST_ETH,
        )

        for acc in [self.module, self.accounting, self.hash_consenus, self.verifier, self.early_adoption, self.fee_distributor, self.fee_oracle]:
            self.shares[acc] = 0

        self.burner.grantRole(self.burner.REQUEST_BURN_SHARES_ROLE(), self.accounting, from_="0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c")

        self.module.grantRole(self.module.MODULE_MANAGER_ROLE(), self.admin, from_=self.admin)
        self.module.activatePublicRelease(from_=self.admin)

        # always start with one NO
        self.flow_add_no()
        # always start with one consensus member
        self.flow_add_consensus_member()

    def post_invariants(self) -> None:
        time_delta = random_int(24 * 60 * 60, 5 * 24 * 60 * 60)
        chain.mine(lambda t: t + time_delta)

    @staticmethod
    def _get_total_bond(keys_count: uint, curve: List[int]) -> uint:
        if keys_count > len(curve):
            return sum(curve) + curve[-1] * (keys_count - len(curve))
        else:
            return sum(curve[:keys_count])

    def _get_frame_info(self, timestamp: uint) -> Tuple[uint, uint]:
        epoch = timestamp_to_epoch(timestamp)
        frame_start_epoch = (epoch - self.initial_epoch) // EPOCHS_PER_FRAME * EPOCHS_PER_FRAME + self.initial_epoch
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
        if no.stuck_keys > 0:
            return 0

        keys_by_eth = self._get_keys_by_eth(no, timestamp, True)
        limit = 2**256 - 1 if no.target_limit_mode == 0 else no.target_limit

        return max(min(no.vetted_keys - no.deposited_keys - no.withdrawn_keys, keys_by_eth - no.deposited_keys, limit - no.deposited_keys), 0)

    def _get_enqueued_keys(self, no_id: int) -> int:
        return sum(item.keys_count for item in self.queue if item.no_id == no_id)

    def _reenqueue(self, no_id: int, depositable_before: int, update_nonce: bool = False) -> None:
        depositable = self._get_depositable_keys(self.node_operators[no_id], chain.blocks["latest"].timestamp)
        enqueued = self._get_enqueued_keys(no_id)

        if depositable_before != depositable:
            assert CSModule.DepositableSigningKeysCountChanged(no_id, depositable) in chain.txs[-1].events
            if update_nonce:
                self.nonce += 1
                assert CSModule.NonceChanged(self.nonce) in chain.txs[-1].events
            if depositable > enqueued:
                self.queue.append(QueueItem(
                    no_id,
                    depositable - enqueued,
                ))

    @flow(max_times=100)
    def flow_add_no(self) -> None:
        keys_count = random_int(1, 20)
        public_keys = [random_bytes(48) for _ in range(keys_count)]
        signatures = [random_bytes(96) for _ in range(keys_count)]
        manager = random_account()
        rewards = random_account() if random.random() < 0.66 else self.accounting
        extended_permissions = random_bool()

        sender = random_account()
        if sender in self.ea_accounts and random.random() < 0.8:
            ea_proof = self.ea_tree.get_proof(self.ea_tree._leaves.index(keccak256(abi.encode(sender))))
            curve = EA_BOND_CURVE
            self.ea_accounts.remove(sender)
        else:
            ea_proof = []
            curve = DEFAULT_BOND_CURVE
        total_bond = self._get_total_bond(keys_count, curve)
        no_id = len(self.node_operators)

        p = random.random()
        if p < 0.33:
            # native ETH
            required_eth = self.accounting.getBondAmountByKeysCount(
                keys_count,
                1 if curve == EA_BOND_CURVE else 0,
            )
            assert abs(required_eth - total_bond) <= 10
            total_bond = required_eth
            shares = ST_ETH.getSharesByPooledEth(total_bond)

            sender.balance += total_bond

            tx = self.module.addNodeOperatorETH(
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
        elif p < 0.66:
            # stETH
            required_eth = self.accounting.getBondAmountByKeysCount(
                keys_count,
                1 if curve == EA_BOND_CURVE else 0,
            )
            assert abs(required_eth - total_bond) <= 10
            total_bond = required_eth
            shares = ST_ETH.getSharesByPooledEth(total_bond)

            sender.balance += total_bond
            ST_ETH.transact(from_=sender, value=total_bond)

            if random_bool():
                ST_ETH.approve(self.accounting, total_bond, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=total_bond,
                    nonce=IERC20Permit(ST_ETH).nonces(sender.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.steth_domain)

            tx = self.module.addNodeOperatorStETH(
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

            required_wst_eth = self.accounting.getBondAmountByKeysCountWstETH(
                keys_count,
                1 if curve == EA_BOND_CURVE else 0,
            )
            assert abs(required_wst_eth - total_bond) <= 10
            total_bond = required_wst_eth
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(total_bond))

            mint_erc20(WST_ETH, sender, total_bond)
            if random_bool():
                WST_ETH.approve(self.accounting, total_bond, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=total_bond,
                    nonce=IERC20Permit(WST_ETH).nonces(sender.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.wsteth_domain)

            tx = self.module.addNodeOperatorWstETH(
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

        self.node_operators[no_id] = NodeOperator(
            id=no_id,
            total_keys=keys_count,
            deposited_keys=0,
            vetted_keys=keys_count,
            withdrawn_keys=0,
            exited_keys=0,
            stuck_keys=0,
            keys=public_keys,
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
        )
        self.shares[self.accounting] += shares
        self.queue.append(QueueItem(no_id, keys_count))
        self.nonce += 1

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
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Added NO {no_id} with {keys_count} keys")

    @flow()
    def flow_no_add_keys(self):
        no = random.choice(list(self.node_operators.values()))
        keys_count = random_int(1, 20)
        public_keys = [random_bytes(48) for _ in range(keys_count)]
        signatures = [random_bytes(96) for _ in range(keys_count)]
        bond_increase = max(
            self._get_total_bond(no.total_keys - no.withdrawn_keys + keys_count, no.bond_curve) - ST_ETH.getPooledEthByShares(no.bond_shares) + self._get_actual_locked_bond(no, chain.blocks["pending"].timestamp),
            0,
        )

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        p = random.random()
        if p < 0.33:
            required_eth = self.accounting.getRequiredBondForNextKeys(no.id, keys_count)
            assert abs(required_eth - bond_increase) <= 10
            bond_increase = required_eth
            shares = ST_ETH.getSharesByPooledEth(bond_increase)

            # native ETH
            no.manager.balance += bond_increase

            tx = self.module.addValidatorKeysETH(
                no.id,
                keys_count,
                b"".join(public_keys),
                b"".join(signatures),
                value=bond_increase,
                from_=no.manager,
            )
            if bond_increase > 0:
                assert CSAccounting.BondDepositedETH(no.id, no.manager.address, bond_increase) in tx.events
            else:
                assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondDepositedETH))
        elif p < 0.66:
            required_eth = self.accounting.getRequiredBondForNextKeys(no.id, keys_count)
            assert abs(required_eth - bond_increase) <= 10
            bond_increase = required_eth
            shares = ST_ETH.getSharesByPooledEth(bond_increase)

            # stETH
            if bond_increase > 0:
                no.manager.balance += bond_increase
                ST_ETH.transact(from_=no.manager, value=bond_increase)

            if random_bool():
                ST_ETH.approve(self.accounting, bond_increase, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=self.accounting.address,
                    value=bond_increase,
                    nonce=IERC20Permit(ST_ETH).nonces(no.manager),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(permit, self.steth_domain)

            tx = self.module.addValidatorKeysStETH(
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
            if bond_increase > 0:
                assert CSAccounting.BondDepositedStETH(no.id, no.manager.address, bond_increase) in tx.events
            else:
                assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondDepositedStETH))
        else:
            # wstETH
            bond_increase = WST_ETH.getWstETHByStETH(bond_increase)

            required_wst_eth = self.accounting.getRequiredBondForNextKeysWstETH(no.id, keys_count)
            assert abs(required_wst_eth - bond_increase) <= 10
            bond_increase = required_wst_eth
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(bond_increase))

            if bond_increase > 0:
                mint_erc20(WST_ETH, no.manager, bond_increase)

            if random_bool():
                WST_ETH.approve(self.accounting, bond_increase, from_=no.manager)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=no.manager.address,
                    spender=self.accounting.address,
                    value=bond_increase,
                    nonce=IERC20Permit(WST_ETH).nonces(no.manager.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = no.manager.sign_structured(permit, self.wsteth_domain)

            tx = self.module.addValidatorKeysWstETH(
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
            if bond_increase > 0:
                assert CSAccounting.BondDepositedWstETH(no.id, no.manager.address, bond_increase) in tx.events
            else:
                assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondDepositedWstETH))

        if no.total_keys == no.vetted_keys:
            # optimistic vetting
            no.vetted_keys += keys_count
            assert CSModule.VettedSigningKeysCountChanged(no.id, no.total_keys + keys_count) in tx.events

        no.total_keys += keys_count
        no.bond_shares += shares
        no.keys.extend(public_keys)
        no.signatures.extend(signatures)
        self.shares[self.accounting] += shares
        self.nonce += 1

        self._reenqueue(no.id, depositable_before)

        assert [CSModule.SigningKeyAdded(no.id, k) for k in public_keys] == [e for e in tx.events if isinstance(e, CSModule.SigningKeyAdded)]
        assert CSModule.TotalSigningKeysCountChanged(no.id, no.total_keys) in tx.events
        if self._get_depositable_keys(no, tx.block.timestamp) != depositable_before:
            assert CSModule.DepositableSigningKeysCountChanged(no.id, self._get_depositable_keys(no, tx.block.timestamp)) in tx.events
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Added {keys_count} keys to NO {no.id}")

    @flow()
    def flow_deposit(self):
        no = random.choice(list(self.node_operators.values()))

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount
        sender = random_account()

        p = random.random()
        if p < 0.33:
            # native ETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            sender.balance += amount
            shares = ST_ETH.getSharesByPooledEth(amount)

            tx = self.module.depositETH(no.id, value=amount, from_=sender)

            if amount > 0:
                assert CSAccounting.BondDepositedETH(no.id, sender.address, amount) in tx.events
            else:
                assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondDepositedETH))
        elif p < 0.66:
            # stETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            shares = ST_ETH.getSharesByPooledEth(amount)

            if amount > 0:
                sender.balance += amount
                ST_ETH.transact(from_=sender, value=amount)

            if random_bool():
                ST_ETH.approve(self.accounting, amount, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=amount,
                    nonce=IERC20Permit(ST_ETH).nonces(sender.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.steth_domain)

            tx = self.module.depositStETH(
                no.id,
                amount,
                CSAccounting.PermitInput(
                    amount,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=sender,
            )

            if amount > 0:
                assert CSAccounting.BondDepositedStETH(no.id, sender.address, amount) in tx.events
            else:
                assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondDepositedStETH))
        else:
            # wstETH
            amount = random_int(0, 1000, edge_values_prob=0.2)
            # trick to use actual stETH shares because of wstETH unwrap logic
            shares = ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(amount))

            if amount > 0:
                mint_erc20(WST_ETH, sender, amount)

            if random_bool():
                WST_ETH.approve(self.accounting, amount, from_=sender)
                permit_signature = b"\x00" * 65
            else:
                permit = Permit(
                    owner=sender.address,
                    spender=self.accounting.address,
                    value=amount,
                    nonce=IERC20Permit(WST_ETH).nonces(sender.address),
                    deadline=uint(2**256 - 1),
                )
                permit_signature = sender.sign_structured(permit, self.wsteth_domain)

            tx = self.module.depositWstETH(
                no.id,
                amount,
                CSAccounting.PermitInput(
                    amount,
                    2**256 - 1,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                ),
                from_=sender,
            )

            if amount > 0:
                assert CSAccounting.BondDepositedWstETH(no.id, sender.address, amount) in tx.events
            else:
                assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondDepositedWstETH))

        self.node_operators[no.id].bond_shares += shares
        self.shares[self.accounting] += shares

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Deposited {amount} to NO {no.id}")

    @flow()
    def flow_no_remove_keys(self):
        try:
            no = random.choice([no for no in self.node_operators.values() if no.total_keys - no.deposited_keys - no.withdrawn_keys > 0])
        except IndexError:
            return "No non-deposited keys"
        keys_count = random_int(1, no.total_keys - no.deposited_keys - no.withdrawn_keys)
        start_index = random_int(0, no.total_keys - no.deposited_keys - no.withdrawn_keys - keys_count) + no.deposited_keys + no.withdrawn_keys

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.module.removeKeys(no.id, start_index, keys_count, from_=no.manager)

        shares = min(ST_ETH.getSharesByPooledEth(KEY_REMOVAL_CHARGE * keys_count), no.bond_shares)
        no.total_keys -= keys_count
        no.vetted_keys = no.total_keys  # optimistic removal
        no.bond_shares -= shares
        self.shares[self.accounting] -= shares
        self.shares[self.charge_penalty_recipient] += shares
        self.nonce += 1

        removed = []

        # queue remains as is, only keys are removed
        for i in range(keys_count, 0, -1):
            if start_index + i < len(no.keys):
                # when not removing last key, move last key to the removed position
                removed.append(no.keys[start_index + i - 1])
                no.keys[start_index + i - 1] = no.keys.pop()
                no.signatures[start_index + i - 1] = no.signatures.pop()
            else:
                # when removing last key, just pop it
                removed.append(no.keys.pop())
                no.signatures.pop()

        self._reenqueue(no.id, depositable_before)

        assert [e for e in tx.events if isinstance(e, CSModule.SigningKeyRemoved)] == [
            CSModule.SigningKeyRemoved(no.id, key)
            for key in removed
        ]
        if KEY_REMOVAL_CHARGE * keys_count > 0:
            assert CSModule.KeyRemovalChargeApplied(no.id) in tx.events
            assert CSAccounting.BondCharged(
                no.id,
                ST_ETH.getPooledEthByShares(ST_ETH.getSharesByPooledEth(KEY_REMOVAL_CHARGE * keys_count)),
                ST_ETH.getPooledEthByShares(shares),
             ) in tx.events
        else:
            assert not any(e for e in tx.events if isinstance(e, CSModule.KeyRemovalChargeApplied))
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondCharged))

        assert CSModule.TotalSigningKeysCountChanged(no.id, no.total_keys) in tx.events
        assert CSModule.VettedSigningKeysCountChanged(no.id, no.vetted_keys) in tx.events
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Removed {keys_count} keys from NO {no.id}")

    @flow()
    def flow_add_consensus_member(self):
        member = random_account()
        quorum = (len(self.consensus_members) + 1) // 2 + 1

        with may_revert(HashConsensus.DuplicateMember) as e:
            tx = self.hash_consenus.addMember(member, quorum, from_=self.admin)

        if member in self.consensus_members:
            assert e.value is not None
            return "Already added"
        else:
            assert e.value is None
            assert HashConsensus.MemberAdded(member.address, len(self.consensus_members) + 1, quorum) in tx.events

            if quorum != self.consensus_quorum:
                assert HashConsensus.QuorumSet(quorum, len(self.consensus_members) + 1, self.consensus_quorum) in tx.events

            self.consensus_members.add(member)
            self.consensus_quorum = quorum

            logger.info(f"Added consensus member {member} with quorum {quorum}")

    @flow()
    def flow_remove_consensus_member(self):
        member = random_account()
        quorum = (len(self.consensus_members) - 1) // 2 + 1

        with may_revert(HashConsensus.NonMember) as e:
            tx = self.hash_consenus.removeMember(member, quorum, from_=self.admin)

        if member in self.consensus_members:
            assert e.value is None
            assert HashConsensus.MemberRemoved(member.address, len(self.consensus_members) - 1, quorum) in tx.events

            if quorum != self.consensus_quorum:
                assert HashConsensus.QuorumSet(quorum, len(self.consensus_members) - 1, self.consensus_quorum) in tx.events

            self.consensus_members.remove(member)
            self.consensus_quorum = quorum

            logger.info(f"Removed consensus member {member} with quorum {quorum}")
        else:
            assert e.value is not None
            return "Not a member"

    @flow()
    def flow_submit_oracle_data(self):
        ref_slot = self._get_frame_info(chain.blocks["pending"].timestamp)[0]
        if ref_slot == self.last_report_ref_slot:
            return "Already reported"
        if len(self.consensus_members) == 0:
            return "No consensus members"

        consensus_version = 1
        distributed = random_int(0, Wei.from_ether(1))

        self.admin.balance += distributed
        ST_ETH.transact(from_=self.admin, value=distributed)
        shares = ST_ETH.getSharesByPooledEth(distributed)
        self.shares[self.admin] += shares

        reports: List[CSFeeOracle.ReportData] = []
        reward_trees: List[MerkleTree] = []
        distributions: List[List[int]] = []
        node_operators: List[List[int]] = []
        # number of pre-generated reports can be adjusted but it will make harder to reach consensus
        for _ in range(2):
            # randomly distribute rewards among N node operators
            distributed = random_int(0, shares)
            N = random_int(0, len(self.node_operators))
            if N == 0 or distributed < N:
                distributed = 0
                distributions.append([])
                node_operators.append([])
            elif N == 1:
                no = random.choice(list(self.node_operators.values()))
                distributions.append([distributed])
                node_operators.append([no.id])
            else:
                cuts = sorted(random.sample(range(1, distributed), N - 1))
                distribution = [cuts[0]] + [cuts[i] - cuts[i - 1] for i in range(1, N - 1)] + [distributed - cuts[-1]]
                distributions.append(distribution)
                node_operators.append(random.sample(list(self.node_operators.keys()), N))

            rewards_tree = MerkleTree()
            for no in self.node_operators.values():
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
            sender = random.choice(self.consensus_members)

            frame_info = self._get_frame_info(chain.blocks["pending"].timestamp)
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
                other_reports = [
                    report_hash
                    for report_hash in votes.keys()
                    if report_hash != current_report_hash
                ]
                if len(other_reports) == 0:
                    continue

                report_hash = random.choice(other_reports)
            except StopIteration:
                report_hash = random.choice(list(votes.keys()))

            tx = self.hash_consenus.submitReport(
                ref_slot,
                report_hash,
                consensus_version,
                from_=sender,
            )

            assert HashConsensus.ReportReceived(frame_info[0], sender.address, report_hash) in tx.events

            for voters in votes.values():
                if sender in voters:
                    voters.remove(sender)
            votes[report_hash].add(sender)

            if any(len(voters) >= self.consensus_quorum for voters in votes.values()):
                assert HashConsensus.ConsensusReached(frame_info[0], report_hash, max(len(voters) for voters in votes.values())) in tx.events
                assert CSFeeOracle.ReportSubmitted(frame_info[0], report_hash, slot_to_timestamp(frame_info[1])) in tx.events
                break
            else:
                assert not any(e for e in tx.events if isinstance(e, HashConsensus.ConsensusReached))
                assert not any(e for e in tx.events if isinstance(e, CSFeeOracle.ReportSubmitted))

        report_hash = next(report_hash for report_hash, voters in votes.items() if len(voters) >= self.consensus_quorum)
        report = next(report for report in reports if keccak256(abi.encode(report)) == report_hash)
        if report.distributed > 0:
            index = reports.index(report)
            self.rewards_tree = reward_trees[index]

            for no, cut in zip(node_operators[index], distributions[index]):
                self.node_operators[no].total_rewards += cut

        ST_ETH.transferShares(self.fee_distributor, report.distributed, from_=self.admin)
        self.shares[self.admin] -= report.distributed
        self.shares[self.fee_distributor] += report.distributed

        sender = random.choice(list(self.consensus_members) + [self.admin])
        tx = self.fee_oracle.submitReportData(
            report,
            1,
            from_=sender,
        )
        self.last_report_ref_slot = ref_slot

        assert CSFeeOracle.ProcessingStarted(ref_slot, report_hash) in tx.events
        if report.distributed > 0:
            assert CSFeeDistributor.DistributionDataUpdated(self.shares[self.fee_distributor], report.treeRoot, report.treeCid) in tx.events
        assert CSFeeDistributor.DistributionLogUpdated(report.logCid) in tx.events
        assert self.fee_oracle.getConsensusReport()[0] == report_hash

        logger.info(f"Submitted oracle data for ref slot {ref_slot} with {report.distributed} stETH shares distributed")

    @flow()
    def flow_pull_rewards(self):
        try:
            no = random.choice([no for no in self.node_operators.values() if keccak256(abi.encode(uint(no.id), uint(no.total_rewards))) in self.rewards_tree._leaves])
        except IndexError:
            return "No rewards"

        tx = self.accounting.pullFeeRewards(
            no.id,
            no.total_rewards,
            self.rewards_tree.get_proof(self.rewards_tree._leaves.index(keccak256(abi.encode(uint(no.id), uint(no.total_rewards))))),
            from_=random_account(),
        )
        claimed = no.total_rewards - no.claimed_rewards
        no.bond_shares += claimed
        no.claimed_rewards = no.total_rewards
        self.shares[self.fee_distributor] -= claimed
        self.shares[self.accounting] += claimed

        if claimed > 0:
            assert CSFeeDistributor.FeeDistributed(no.id, claimed) in tx.events

        logger.info(f"Pulled {claimed} stETH shares for NO {no.id}")

    @flow()
    def flow_claim_rewards(self):
        try:
            no = random.choice([no for no in self.node_operators.values() if keccak256(abi.encode(uint(no.id), uint(no.total_rewards))) in self.rewards_tree._leaves])
        except IndexError:
            return "No rewards"
        sender = random.choice([no.manager, no.rewards_account])
        t = chain.blocks["pending"].timestamp

        proof = self.rewards_tree.get_proof(self.rewards_tree._leaves.index(keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))))
        if len(proof) == 0:
            # rewards don't get pulled with empty proof
            claimable_shares = max(no.bond_shares - ST_ETH.getSharesByPooledEth(self._get_total_bond(no.total_keys - no.withdrawn_keys, no.bond_curve) + self._get_actual_locked_bond(no, t)), 0)
            pulled_shares = 0
        else:
            claimable_shares = max(no.bond_shares + no.total_rewards - no.claimed_rewards - ST_ETH.getSharesByPooledEth(self._get_total_bond(no.total_keys - no.withdrawn_keys, no.bond_curve) + self._get_actual_locked_bond(no, t)), 0)
            pulled_shares = no.total_rewards - no.claimed_rewards
        shares_to_claim = random_int(0, claimable_shares + 10, edge_values_prob=0.1)

        shares_before = ST_ETH.sharesOf(self.accounting)
        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        p = random.random()
        with may_revert((CSAccounting.NothingToClaim, IUnstETH.RequestAmountTooSmall)) as ex:
            if p < 0.33:
                # unstETH
                balance_before = 0
                tx = self.module.claimRewardsUnstETH(
                    no.id,
                    ST_ETH.getPooledEthByShares(shares_to_claim),
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                claimed_shares = shares_before + pulled_shares - ST_ETH.sharesOf(self.accounting)
            elif p < 0.66:
                # stETH
                balance_before = ST_ETH.sharesOf(no.rewards_account)
                tx = self.module.claimRewardsStETH(
                    no.id,
                    ST_ETH.getPooledEthByShares(shares_to_claim),
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                e = [e for e in tx.raw_events if isinstance(e, UnknownEvent) and e.topics[0] == bytes.fromhex("9d9c909296d9c674451c0c24f02cb64981eb3b727f99865939192f880a755dcb")][-1]
                claimed_shares = abi.decode(e.data, [uint])

                assert CSAccounting.BondClaimedStETH(no.id, no.rewards_account.address, ST_ETH.getPooledEthByShares(claimed_shares)) in tx.events
            else:
                # wstETH
                balance_before = WST_ETH.balanceOf(no.rewards_account)
                tx = self.module.claimRewardsWstETH(
                    no.id,
                    shares_to_claim,
                    no.total_rewards,
                    proof,
                    from_=sender,
                )
                claimed_shares = shares_before + pulled_shares - ST_ETH.sharesOf(self.accounting)

                assert CSAccounting.BondClaimedWstETH(no.id, no.rewards_account.address, claimed_shares) in tx.events

        if isinstance(ex.value, CSAccounting.NothingToClaim):
            assert min(shares_to_claim, claimable_shares) == 0 or p < 0.66 and ST_ETH.getSharesByPooledEth(ST_ETH.getPooledEthByShares(shares_to_claim)) == 0
            return "Nothing to claim"
        elif isinstance(ex.value, IUnstETH.RequestAmountTooSmall):
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
            self.shares[self.fee_distributor] -= pulled_shares
            self.shares[self.accounting] += pulled_shares

            if pulled_shares > 0:
                assert CSFeeDistributor.FeeDistributed(no.id, pulled_shares) in tx.events

        # claim part
        print(f"error: {claimed_shares - shares_to_claim}")
        assert claimed_shares <= min(shares_to_claim, claimable_shares)
        assert abs(claimed_shares - shares_to_claim) <= 11
        no.bond_shares -= claimed_shares

        self.shares[self.accounting] -= claimed_shares
        if p < 0.33:
            last_withdrawal_id = abi.decode(UNST_ETH.call(abi.encode_with_signature("getLastRequestId()")), [uint])
            assert UNST_ETH.getWithdrawalStatus([last_withdrawal_id])[0].amountOfShares == claimed_shares
        elif p < 0.66:
            if no.rewards_account != self.accounting:
                assert ST_ETH.sharesOf(no.rewards_account) == balance_before + claimed_shares
            else:
                assert ST_ETH.sharesOf(no.rewards_account) == balance_before + pulled_shares
            self.shares[no.rewards_account] += claimed_shares
        else:
            assert WST_ETH.balanceOf(no.rewards_account) == balance_before + claimed_shares

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Claimed {claimed_shares} stETH shares for NO {no.id}")

    @flow()
    def flow_report_stealing(self):
        no = random.choice(list(self.node_operators.values()))
        amount = random_int(0, Wei.from_ether(3), edge_values_prob=0.1)
        block_hash = random_bytes(32)

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount
        with may_revert(CSModule.InvalidAmount) as e:
            tx = self.module.reportELRewardsStealingPenalty(
                no.id,
                block_hash,
                amount,
                from_=self.admin,
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
        no.lock_expiry = tx.block.timestamp + self.bond_lock_retention_period

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        assert CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry) in tx.events
        assert CSModule.ELRewardsStealingPenaltyReported(no.id, block_hash, amount) in tx.events

        logger.info(f"Reported {amount} wei stealing penalty for NO {no.id}")

    @flow()
    def flow_cancel_stealing_penalty(self):
        t = chain.blocks["pending"].timestamp
        try:
            no = random.choice([no for no in self.node_operators.values() if self._get_actual_locked_bond(no, t)])
        except IndexError:
            return "No NO with locked bond"
        locked = self._get_actual_locked_bond(no, t)
        amount = random_int(1, locked, edge_values_prob=0.2)

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.module.cancelELRewardsStealingPenalty(
            no.id,
            amount,
            from_=self.admin,
        )

        no.locked_bond -= amount
        if no.locked_bond == 0:
            no.lock_expiry = 0

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        if amount == locked:
            assert CSAccounting.BondLockRemoved(no.id) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockChanged))
        else:
            assert CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockRemoved))
        assert CSModule.ELRewardsStealingPenaltyCancelled(no.id, amount) in tx.events

        logger.info(f"Canceled {amount} wei stealing penalty for NO {no.id}")

    @flow()
    def flow_settle_stealing_penalty(self):
        depositable_before = {no.id: self.module.getNodeOperator(no.id).depositableValidatorsCount for no in self.node_operators.values()}
        tx = self.module.settleELRewardsStealingPenalty(list(self.node_operators.keys()), from_=self.admin)

        for no in self.node_operators.values():
            if self._get_actual_locked_bond(no, tx.block.timestamp) > 0:
                shares = ST_ETH.getSharesByPooledEth(no.locked_bond)
                no.bond_curve = DEFAULT_BOND_CURVE
                assert self.accounting.getBondCurveId(no.id) == 0

                shares = min(shares, no.bond_shares)
                self.shares[self.accounting] -= shares
                self.shares[self.burner] += shares
                no.bond_shares -= shares
                no.locked_bond = 0
                no.lock_expiry = 0

                self._reenqueue(no.id, depositable_before[no.id], update_nonce=True)

                assert CSAccounting.BondLockRemoved(no.id) in tx.events
                assert CSModule.ELRewardsStealingPenaltySettled(no.id) in tx.events
            else:
                assert CSAccounting.BondLockRemoved(no.id) not in tx.events
                assert CSModule.ELRewardsStealingPenaltySettled(no.id) not in tx.events

        logger.info(f"Settled stealing penalties")

    @flow()
    def flow_compensate_stealing_penalty(self):
        t = chain.blocks["pending"].timestamp
        try:
            no = random.choice([no for no in self.node_operators.values() if self._get_actual_locked_bond(no, t) > 0])
        except IndexError:
            return "No NO with locked bond"
        locked = self._get_actual_locked_bond(no, t)
        amount = random_int(1, locked, edge_values_prob=0.2)
        no.manager.balance += amount

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.module.compensateELRewardsStealingPenalty(no.id, value=amount, from_=no.manager)

        no.locked_bond -= amount
        self.balances[self.el_rewards_vault] += amount
        if no.locked_bond == 0:
            no.lock_expiry = 0

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        if amount == locked:
            assert CSAccounting.BondLockRemoved(no.id) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockChanged))
        else:
            assert CSAccounting.BondLockChanged(no.id, no.locked_bond, no.lock_expiry) in tx.events
            assert not any(e for e in tx.events if isinstance(e, CSAccounting.BondLockRemoved))

        assert CSAccounting.BondLockCompensated(no.id, amount) in tx.events

        logger.info(f"Compensated {amount} wei stealing penalty for NO {no.id}")

    @flow()
    def flow_obtain_deposit_data(self):
        # CSM sees different number of depositable keys than we do because depositable keys are stored in the contract
        # and not updated on EL stealing retention period end
        depositable_keys = {
            no.id: self.module.getNodeOperator(no.id).depositableValidatorsCount
            for no in self.node_operators.values()
        }
        t = chain.blocks["pending"].timestamp
        deposits_count = random_int(0, sum(self._get_depositable_keys(no, t) for no in self.node_operators.values()))

        with may_revert(CSModule.NotEnoughKeys) as e:
            tx = self.module.obtainDepositData(
                deposits_count,
                b"",
                from_=STAKING_ROUTER,
            )

        if e.value is not None:
            # total depositable keys is less than requested
            assert sum(
                min(depositable_keys[no.id], self._get_enqueued_keys(no.id))
                for no in self.node_operators.values()
            ) < deposits_count
            return "Not enough keys to deposit"

        if deposits_count != 0:
            self.nonce += 1
            assert CSModule.NonceChanged(self.nonce) in tx.events

        keys = bytearray(b"")
        signatures = bytearray(b"")
        deposited = 0

        while deposits_count > deposited:
            item = self.queue[0]
            no = self.node_operators[item.no_id]
            keys_count = min(
                item.keys_count,
                deposits_count - deposited,
                depositable_keys[item.no_id],
            )
            if item.keys_count == keys_count:
                # consume the whole item
                keys += b"".join(no.keys[no.deposited_keys + no.withdrawn_keys:no.deposited_keys + no.withdrawn_keys + keys_count])
                signatures += b"".join(no.signatures[no.deposited_keys + no.withdrawn_keys:no.deposited_keys + no.withdrawn_keys + keys_count])
                self.queue.popleft()
                no.deposited_keys += keys_count
            else:
                # consume part of the item
                keys += b"".join(no.keys[no.deposited_keys + no.withdrawn_keys:no.deposited_keys + no.withdrawn_keys + keys_count])
                signatures += b"".join(no.signatures[no.deposited_keys + no.withdrawn_keys:no.deposited_keys + no.withdrawn_keys + keys_count])
                item.keys_count -= keys_count
                no.deposited_keys += keys_count

                if deposited + keys_count != deposits_count:
                    # the rest of the keys of the given validator are not depositable, consume the whole item
                    self.queue.popleft()

            deposited += keys_count
            depositable_keys[item.no_id] -= keys_count

            if keys_count > 0:
                assert CSModule.DepositedSigningKeysCountChanged(no.id, no.deposited_keys + no.withdrawn_keys) in tx.events
                assert CSModule.DepositableSigningKeysCountChanged(no.id, depositable_keys[item.no_id]) in tx.events

        assert keys == tx.return_value[0]
        assert signatures == tx.return_value[1]

        logger.info(f"Obtained deposit data for {deposits_count} keys")

    @flow()
    def flow_normalize_queue(self):
        no = random.choice(list(self.node_operators.values()))

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount
        tx = self.module.normalizeQueue(no.id, from_=no.manager)

        # contract sees different number of depositable keys than we do
        depositable = self.module.getNodeOperator(no.id).depositableValidatorsCount
        enqueued = self._get_enqueued_keys(no.id)
        if enqueued < depositable:
            self.queue.append(QueueItem(no.id, depositable - enqueued))

        depositable = self._get_depositable_keys(self.node_operators[no.id], chain.blocks["latest"].timestamp)
        if depositable != depositable_before:
            self.nonce += 1
            assert CSModule.DepositableSigningKeysCountChanged(no.id, depositable) in tx.events
            assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Normalized queue for NO {no.id}")

    @flow()
    def flow_clean_deposit_queue(self):
        depositable_keys = {
            no.id: self.module.getNodeOperator(no.id).depositableValidatorsCount
            for no in self.node_operators.values()
        }
        max_items = random_int(1, max(len(self.queue), 1))

        tx = self.module.cleanDepositQueue(max_items, from_=random_account())

        enqueued_keys = defaultdict(int)

        new_queue = deque()
        removed_items = 0
        last_removal_pos = 0
        for i, item in enumerate(self.queue):
            if i >= max_items:
                new_queue.append(item)
                continue

            if depositable_keys[item.no_id] > enqueued_keys[item.no_id]:
                enqueued_keys[item.no_id] += item.keys_count
                new_queue.append(item)
            else:
                removed_items += 1
                last_removal_pos = i + 1

        self.queue = new_queue
        assert tx.return_value == (removed_items, last_removal_pos)

        logger.info(f"Cleaned deposit queue")

    @flow()
    def flow_update_target_validators_limit(self):
        no = random.choice(list(self.node_operators.values()))
        mode = random_int(0, 2)
        limit = random_int(0, 100)

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.module.updateTargetValidatorsLimits(no.id, mode, limit, from_=STAKING_ROUTER)

        if mode == 0:
            limit = 0

        if no.target_limit != limit or no.target_limit_mode != mode:
            no.target_limit = limit
            no.target_limit_mode = mode

            self._reenqueue(no.id, depositable_before)

            assert CSModule.TargetValidatorsCountChanged(no.id, mode, limit) in tx.events

            # updated even if depositable didn't change
            self.nonce += 1
            assert CSModule.NonceChanged(self.nonce) in tx.events
        else:
            assert not any(e for e in tx.events if isinstance(e, CSModule.TargetValidatorsCountChanged))
            assert not any(e for e in tx.events if isinstance(e, CSModule.NonceChanged))

        logger.info(f"Updated target validators limit for NO {no.id}")

    @flow()
    def flow_update_stuck_validators_count(self):
        no = random.choice(list(self.node_operators.values()))
        count = random_int(0, no.deposited_keys)

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.module.updateStuckValidatorsCount(
            no.id.to_bytes(8, "big"),
            count.to_bytes(16, "big"),
            from_=STAKING_ROUTER,
        )

        if count != no.stuck_keys:
            no.stuck_keys = count
            assert CSModule.StuckSigningKeysCountChanged(no.id, count) in tx.events

            self._reenqueue(no.id, depositable_before)

        self.nonce += 1
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Updated stuck validators count for NO {no.id}")

    @flow()
    def flow_update_exited_validators_count(self):
        no = random.choice(list(self.node_operators.values()))
        count = random_int(0, no.withdrawn_keys - no.exited_keys)

        tx = self.module.updateExitedValidatorsCount(
            no.id.to_bytes(8, "big"),
            (no.exited_keys + count).to_bytes(16, "big"),
            from_=STAKING_ROUTER,
        )

        no.exited_keys += count
        self.nonce += 1

        if count > 0:
            assert CSModule.ExitedSigningKeysCountChanged(no.id, no.exited_keys) in tx.events

        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Updated exited validators count for NO {no.id}")

    @flow()
    def flow_decrease_vetted_signing_keys_count(self):
        no = random.choice(list(self.node_operators.values()))
        count = random_int(no.deposited_keys + no.withdrawn_keys, no.vetted_keys)

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert(CSModule.InvalidVetKeysPointer) as e:
            tx = self.module.decreaseVettedSigningKeysCount(
                no.id.to_bytes(8, "big"),
                count.to_bytes(16, "big"),
                from_=STAKING_ROUTER,
            )

        if count == no.vetted_keys:
            assert e.value is not None
            return "Vetted keys same"
        assert e.value is None

        no.vetted_keys = count
        self._reenqueue(no.id, depositable_before)
        self.nonce += 1

        assert CSModule.VettedSigningKeysCountChanged(no.id, count) in tx.events
        assert CSModule.VettedSigningKeysCountDecreased(no.id) in tx.events
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Decreased vetted signing keys count for NO {no.id} to {count}")

    @flow()
    def flow_unsafe_update_validators_count(self):
        no = random.choice(list(self.node_operators.values()))
        stuck = random_int(0, no.deposited_keys)
        exited = random_int(0, no.withdrawn_keys - no.exited_keys)

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        tx = self.module.unsafeUpdateValidatorsCount(
            no.id,
            exited,
            stuck,
            from_=STAKING_ROUTER,
        )

        if exited != no.exited_keys:
            no.exited_keys = exited
            assert CSModule.ExitedSigningKeysCountChanged(no.id, exited) in tx.events

        if stuck != no.stuck_keys:
            no.stuck_keys = stuck
            assert CSModule.StuckSigningKeysCountChanged(no.id, stuck) in tx.events

            self._reenqueue(no.id, depositable_before)

        self.nonce += 1
        assert CSModule.NonceChanged(self.nonce) in tx.events

        logger.info(f"Updated stuck and exited validators count for NO {no.id}")

    @flow()
    def flow_process_historical_withdrawal_proof(self):
        try:
            no = random.choice([no for no in self.node_operators.values() if no.deposited_keys + no.withdrawn_keys > 0])
        except IndexError:
            return "No NO with deposited keys"
        index = random_int(0, no.deposited_keys + no.withdrawn_keys - 1)
        slashed = random_bool() or no.slashed[index]
        amount = random_int(1, (Wei.from_ether(32) if not slashed else Wei.from_ether(31)) // 10 ** 9, max_prob=0.2)

        slot = timestamp_to_slot(chain.blocks["latest"].timestamp)

        validator = Validator(
            no.keys[index],
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

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert((CSModule.AlreadySubmitted, CSVerifier.PartialWithdrawal)) as e:
            tx = self.verifier.processHistoricalWithdrawalProof(
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
        assert CSModule.WithdrawalSubmitted(no.id, index, amount * 10 ** 9, no.keys[index]) in tx.events

        no.deposited_keys -= 1
        no.withdrawn_keys += 1

        max_amount = (Wei.from_ether(31) if no.slashed[index] else Wei.from_ether(32)) // 10 ** 9  # if previously slashed, don't slash again; in gwei
        if amount < max_amount:
            # steth burned
            shares = min(ST_ETH.getSharesByPooledEth((max_amount - amount) * 10 ** 9), no.bond_shares)
            self.shares[self.accounting] -= shares
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

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Processed historical withdrawal proof for NO {no.id}")

    @flow()
    def flow_process_withdrawal_proof(self):
        try:
            no = random.choice([no for no in self.node_operators.values() if no.deposited_keys + no.withdrawn_keys > 0])
        except IndexError:
            return "No NO with deposited keys"
        index = random_int(0, no.deposited_keys + no.withdrawn_keys - 1)

        self._withdraw(no, index)

    def _withdraw(self, no: NodeOperator, index: int, update_state: bool = True, full_withdraw: bool = False):
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
            no.keys[index],
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

        # historical summaries
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

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert((CSModule.AlreadySubmitted, CSVerifier.PartialWithdrawal)) as e:
            tx = self.verifier.processWithdrawalProof(
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
        assert CSModule.WithdrawalSubmitted(no.id, index, amount * 10 ** 9, no.keys[index]) in tx.events

        if not update_state:
            return

        no.deposited_keys -= 1
        no.withdrawn_keys += 1

        max_amount = (Wei.from_ether(31) if no.slashed[index] else Wei.from_ether(32)) // 10 ** 9  # if previously slashed, don't slash again; in gwei
        if amount < max_amount:
            # steth burned
            shares = min(ST_ETH.getSharesByPooledEth((max_amount - amount) * 10 ** 9), no.bond_shares)
            self.shares[self.accounting] -= shares
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

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Processed withdrawal proof for NO {no.id}")

    @flow()
    def flow_process_slashing_proof(self):
        try:
            no = random.choice([no for no in self.node_operators.values() if no.deposited_keys > 0])
        except IndexError:
            return "No NO with deposited keys"
        index = random_int(0, no.deposited_keys + no.withdrawn_keys - 1)

        slot = timestamp_to_slot(chain.blocks["latest"].timestamp)

        validator = Validator(
            no.keys[index],
            b"\x01" + 11 * b"\x00" + bytes(LIDO_LOCATOR.withdrawalVault()),
            random_int(0, 2**64 - 1),
            True,
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

        # withdrawals + historical summaries
        for _ in range(4 + 8):
            state_tree.add_leaf(random_bytes(32))

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

        depositable_before = self.module.getNodeOperator(no.id).depositableValidatorsCount

        with may_revert(CSModule.AlreadySubmitted) as e:
            tx = self.verifier.processSlashingProof(
                CSVerifier.ProvableBeaconBlockHeader(
                    block_header,
                    tx.block.timestamp,
                ),
                CSVerifier.SlashingWitness(
                    validator_index,
                    validator.withdrawalCredentials,
                    validator.effectiveBalance,
                    validator.activationEligibilityEpoch,
                    validator.activationEpoch,
                    validator.exitEpoch,
                    validator.withdrawableEpoch,
                    state_tree.get_proof(state_tree.leaves.index(validator_root)),
                ),
                no.id,
                index,
                from_=random_account(),
            )

        if no.slashed[index]:
            assert e.value == CSModule.AlreadySubmitted()
            return "Already submitted"
        assert e.value is None

        shares = min(ST_ETH.getSharesByPooledEth(Wei.from_ether(1)), no.bond_shares)
        self.shares[self.accounting] -= shares
        self.shares[self.burner] += shares
        no.bond_shares -= shares

        no.slashed[index] = True
        # bond curve is reset later on validator withdrawal

        assert CSModule.InitialSlashingSubmitted(no.id, index, no.keys[index]) in tx.events

        burned = ST_ETH.getPooledEthByShares(shares)
        if burned > 0:
            assert CSAccounting.BondBurned(
                no.id,
                ST_ETH.getPooledEthByShares(ST_ETH.getSharesByPooledEth(Wei.from_ether(1))),
                burned,
            ) in tx.events

        self._reenqueue(no.id, depositable_before, update_nonce=True)

        logger.info(f"Processed slashing proof for NO {no.id}")

    @flow()
    def flow_transfer_steth(self):
        amount = random_int(1, Wei.from_ether(1))
        acc = random_account()
        acc.balance += amount

        shares = ILido(ST_ETH).submit(Address.ZERO, from_=acc, value=amount).return_value

        ST_ETH.transferShares(self.accounting, shares, from_=acc)

        self.shares[self.accounting] += shares

        logger.info(f"Transferred {shares} to accounting")

    @flow()
    def flow_transfer_wst_eth(self):
        amount = random_int(1, 10000)
        mint_erc20(WST_ETH, self.accounting, amount)

    @flow()
    def flow_steth_submit(self):
        amount = random_int(1, 10000)
        acc = random_account(chain=chain)
        acc.balance += amount

        tx = ILido(ST_ETH).submit(Address.ZERO, from_=acc, value=amount)

        self.shares[acc] += tx.return_value

        t = tx.block.timestamp

        for no in self.node_operators.values():
            unbonded = no.total_keys - no.withdrawn_keys - self._get_keys_by_eth(no, t, False)
            assert self.accounting.getUnbondedKeysCountToEject(no.id) == max(unbonded, 0)
            assert self.accounting.getUnbondedKeysCount(no.id) == max(no.total_keys - no.withdrawn_keys - self._get_keys_by_eth(no, t, True), 0)

    @invariant()
    def invariant_balances(self):
        assert self.balances[self.module] == 0

        for acc, balance in self.balances.items():
            assert acc.balance == balance

    @invariant()
    def invariant_shares(self):
        assert self.shares[self.module] == 0

        for acc, shares in self.shares.items():
            assert ST_ETH.sharesOf(acc) == shares

    @invariant()
    def invariant_bond(self):
        t = chain.blocks["latest"].timestamp

        for no in self.node_operators.values():
            assert self.accounting.getBondShares(no.id) == no.bond_shares
            assert self.accounting.getLockedBondInfo(no.id) == CSAccounting.BondLock(no.locked_bond, no.lock_expiry)
            assert self._get_actual_locked_bond(no, t) == self.accounting.getActualLockedBond(no.id)

        assert self.accounting.totalBondShares() == sum(no.bond_shares for no in self.node_operators.values())
        assert ST_ETH.sharesOf(self.fee_distributor) == sum(no.total_rewards - no.claimed_rewards for no in self.node_operators.values())

    @invariant()
    def invariant_node_operators(self):
        with chain.snapshot_and_revert():
            for no in self.node_operators.values():
                assert self._get_enqueued_keys(no.id) == self.module.getNodeOperator(no.id).enqueuedCount

                # workaround for depositableValidatorsCount is being updated after bond lock retention period end
                self.module.normalizeQueue(no.id, from_=random_account())

            t = chain.blocks["latest"].timestamp
            depositable_sum = 0
            deposited_sum = 0
            exited_sum = 0

            for no in self.node_operators.values():
                assert b"".join(no.keys) == self.module.getSigningKeys(no.id, 0, no.total_keys)
                assert (b"".join(no.keys), b"".join(no.signatures)) == self.module.getSigningKeysWithSignatures(no.id, 0, no.total_keys)
                info = self.module.getNodeOperator(no.id)
                assert no.total_keys == info.totalAddedKeys
                assert no.withdrawn_keys == info.totalWithdrawnKeys
                assert no.stuck_keys == info.stuckValidatorsCount
                assert no.target_limit == info.targetLimit
                assert no.target_limit_mode == info.targetLimitMode
                assert no.manager.address == info.managerAddress
                assert no.rewards_account.address == info.rewardAddress
                assert self._get_depositable_keys(no, t) == info.depositableValidatorsCount
                assert no.deposited_keys + no.withdrawn_keys == info.totalDepositedKeys  # CSM counts withdrawn keys as deposited
                assert no.exited_keys == info.totalExitedKeys
                assert no.vetted_keys == info.totalVettedKeys
                assert self.module.getNodeOperatorNonWithdrawnKeys(no.id) == no.total_keys - no.withdrawn_keys
                # enqueued keys already checked before workaround

                unbonded = no.total_keys - no.withdrawn_keys - self._get_keys_by_eth(no, t, False)
                assert self.accounting.getUnbondedKeysCountToEject(no.id) == max(unbonded, 0)
                assert self.accounting.getUnbondedKeysCount(no.id) == max(no.total_keys - no.withdrawn_keys - self._get_keys_by_eth(no, t, True), 0)

                summary = self.module.getNodeOperatorSummary(no.id)
                if unbonded > no.total_keys - no.deposited_keys - no.withdrawn_keys:
                    target_limit_mode = 2

                    if no.target_limit_mode == 2:
                        target_limit = min(no.target_limit, no.total_keys - no.withdrawn_keys - unbonded)
                    else:
                        target_limit = no.total_keys - no.withdrawn_keys - unbonded
                else:
                    target_limit_mode = no.target_limit_mode
                    target_limit = no.target_limit

                assert summary == (
                    target_limit_mode,
                    target_limit,
                    no.stuck_keys,
                    0,
                    0,
                    no.exited_keys,
                    no.deposited_keys + no.withdrawn_keys,
                    self._get_depositable_keys(no, t)
                )

                depositable_sum += info.depositableValidatorsCount
                deposited_sum += info.totalDepositedKeys
                exited_sum += info.totalExitedKeys

                for key in range(no.total_keys):
                    assert no.slashed[key] == self.module.isValidatorSlashed(no.id, key)
                    assert no.withdrawn[key] == self.module.isValidatorWithdrawn(no.id, key)

                assert self.accounting.getBondSummary(no.id) == (
                    ST_ETH.getPooledEthByShares(no.bond_shares),
                    self._get_total_bond(no.total_keys - no.withdrawn_keys, no.bond_curve) + self._get_actual_locked_bond(no, t)
                )
                assert self.accounting.getBondSummaryShares(no.id) == (
                    no.bond_shares,
                    ST_ETH.getSharesByPooledEth(
                        self._get_total_bond(no.total_keys - no.withdrawn_keys, no.bond_curve) + self._get_actual_locked_bond(no, t)
                    )
                )

            assert self.module.getStakingModuleSummary() == (exited_sum, deposited_sum, depositable_sum)

    @invariant()
    def invariant_queue(self):
        head, tail = self.module.depositQueue()
        current = head
        i = 0

        while current != tail:
            item = self.module.depositQueueItem(current)
            no_id = item >> (256 - 64)
            keys_count = item >> (256 - 64 - 64) & (2**64 - 1)

            assert self.queue[i] == QueueItem(no_id, keys_count)

            current = item & (2**128 - 1)
            i += 1

        assert self.module.depositQueueItem(tail) == 0
        assert len(self.queue) == i

    @invariant()
    def invariant_nonce(self):
        assert self.module.getNonce() == self.nonce

    # not used in general fuzzer run
    #@invariant()
    def invariant_all_withdrawn(self):
        with chain.snapshot_and_revert():
            chain.mine(lambda t: t + self.bond_lock_retention_period)

            self.module.setKeyRemovalCharge(0, from_=self.admin)

            for no in self.node_operators.values():
                for index in range(no.deposited_keys + no.withdrawn_keys):
                    if not no.withdrawn[index]:
                        self._withdraw(no, index, update_state=False, full_withdraw=True)

                to_remove = no.total_keys - no.deposited_keys - no.withdrawn_keys
                if to_remove > 0:
                    self.module.removeKeys(no.id, no.deposited_keys + no.withdrawn_keys, to_remove, from_=no.manager)

                assert self.accounting.getBondShares(no.id) == no.bond_shares
                assert self.fee_distributor.distributedShares(no.id) == no.claimed_rewards
                assert self.module.getNodeOperatorNonWithdrawnKeys(no.id) == 0
                claimable_shares = no.bond_shares + no.total_rewards - no.claimed_rewards
                with may_revert(CSAccounting.NothingToClaim):
                    if keccak256(abi.encode(uint(no.id), uint(no.total_rewards))) in self.rewards_tree._leaves:
                        proof = self.rewards_tree.get_proof(self.rewards_tree._leaves.index(keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))))
                        if len(proof) == 0:
                            # cannot claim if the proof is empty, have to pull the rewards first
                            self.accounting.pullFeeRewards(no.id, no.total_rewards, proof, from_=random_account())
                    else:
                        proof = []

                    tx = self.module.claimRewardsStETH(
                        no.id,
                        2**256 - 1,
                        no.total_rewards,
                        (
                            self.rewards_tree.get_proof(self.rewards_tree._leaves.index(keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))))
                            if keccak256(abi.encode(uint(no.id), uint(no.total_rewards))) in self.rewards_tree._leaves
                            else []
                        ),
                        from_=no.manager,
                    )
                    e = [e for e in tx.raw_events if isinstance(e, UnknownEvent) and e.topics[0] == bytes.fromhex("9d9c909296d9c674451c0c24f02cb64981eb3b727f99865939192f880a755dcb")][-1]
                    claimed_shares = abi.decode(e.data, [uint])
                    assert claimed_shares == claimable_shares

            assert self.accounting.totalBondShares() == ST_ETH.sharesOf(self.accounting)
            assert ST_ETH.sharesOf(self.accounting) == 0


@chain.connect(fork="http://localhost:8545", accounts=20)
def test_csm():
    CsmFuzzTest().run(100, 1000)
