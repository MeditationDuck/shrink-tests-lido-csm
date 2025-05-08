from dataclasses import dataclass

from typing import Callable, Dict, Tuple
from ordered_set import OrderedSet
from wake.testing import *
from wake.testing.fuzzing import *
from wake.development.internal import ExternalEvent
from pytypes.core.contracts._0_8_9.interfaces.IStakingModule import IStakingModule
from pytypes.core.contracts._0_8_9.proxy.OssifiableProxy import OssifiableProxy
from pytypes.core.contracts._0_8_9.test_helpers.StakingModuleMock import StakingModuleMock
from pytypes.core.contracts.common.lib.MinFirstAllocationStrategy import (
    MinFirstAllocationStrategy,
)
from pytypes.tests.migrated_contracts.NodeOperatorsRegistryMigrated import (
    NodeOperatorsRegistryMigrated,
)
from pytypes.core.contracts._0_8_9.oracle.ValidatorsExitBusOracle import (
    ValidatorsExitBusOracle,
)
from pytypes.core.contracts._0_8_9.oracle.HashConsensus import HashConsensus
from pytypes.core.contracts._0_8_9.oracle.AccountingOracle import (
    AccountingOracle,
    ILegacyOracle,
)
from pytypes.core.contracts._0_8_9.sanity_checks.OracleReportSanityChecker import (
    OracleReportSanityChecker,
    LimitsList,
)
from pytypes.tests.migrated_contracts.utils_and_lib.SigningKeys import SigningKeys
from pytypes.core.contracts._0_8_9.lib.PositiveTokenRebaseLimiter import (
    TokenRebaseLimiterData,
)
import copy
from pytypes.csm.src.CSModule import CSModule
from .csm_fuzz import CsmFuzzTest

from .beacon import BeaconChain
from .utils import (
    deploy_deposit_security_module,
    deploy_node_operator_registry,
    deploy_staking_router,
    logger,
    revert_handler,
    sig_to_compact,
    update_locator,
    deploy_accounting_oracle,
    deploy_hash_consensus,
    deploy_validator_exit_bus_oracle,
    appId,
    access_control_overwrite,
)
from .fork_data import *
from .csm_fuzz import KeyInfo, KeyState, CSM_MAX_COUNT, QueueItem
from pytypes.csm.src.CSAccounting import CSAccounting


TEST_OLD_SOLIDITY = True
CALL_UNSAFE = False
DEPLOY_WQ = True
MAX_STAKING_MODULES_COUNT = 4  # for each module
USE_UPDATE_REFUNDED = True

NOR_NO_AVG_COUNT = 2
NOR_MAX_COUNT = 1

TOTAL_BASIS_POINTS = 10_000  # hardcoded
FEE_PRECISION_POINTS = 10**20  # sr_hardcoded
INITIAL_VALIDATORS_COUNT = 500
NO_EXTRA_DATA_STUCK_EXCLUDE_PROB = 0.1
NO_EXTRA_DATA_EXITED_EXCLUDE_PROB = 0.1
MAX_NOS_PER_EXTRA_DATA_ITEM = 100


@dataclass
class NodeOperator:
    id: int
    name: str
    rewards_account: Account
    active: bool
    exited_keys_count: uint64  #
    deposited_keys_count: uint64  # TOTAL_DEPOSITED_KEYS_COUNT_OFFSET
    vetted_keys_count: uint64  # TOTAL_VETTED_KEYS_COUNT_OFFSET
    total_keys_count: uint64  # TOTAL_KEYS_COUNT_OFFSET
    stuck_keys_count: uint64  # STUCK_VALIDATORS_COUNT_OFFSET
    refunded_keys_count: uint64  # REFUNDED_VALIDATORS_COUNT_OFFSET
    target_limit_mode: uint64  # TARGET_LIMIT_MODE_OFFSET
    target_limit: uint64  # TARGET_VALIDATORS_COUNT_OFFSET
    max_keys_count: uint64  # MAX_VALIDATORS_COUNT_OFFSET
    summary_max_keys_count: uint64  # SUMMARY_MAX_VALIDATORS_COUNT_OFFSET
    stuck_penalty_end_timestamp: uint64  # STUCK_PENALTY_END_TIMESTAMP_OFFSET
    keys: List[KeyInfo]  # user stored keys
    exit_requested_key_count: uint64  # EXIT_REQUESTED_VALIDATORS_COUNT_OFFSET
    rewards_account_share: uint256


@dataclass
class StakingModule:
    id: int
    is_csm: bool
    nonce: int
    node_operators: Dict[int, NodeOperator]
    staking_module: StakingRouter.StakingModule
    total_exited_keys_count: uint256
    total_exited_keys_count_in_sr: uint256
    total_deposited_keys_count: uint256
    max_deposits_per_block: uint256
    total_depostable_keys_count: uint256
    stake_share_limit: int
    staking_module_fee: int
    treasury_fee: int
    reward_distribution_state: NodeOperatorsRegistryMigrated.RewardDistributionState
    active_node_operators: int
    stuck_penalty_delay: uint256


@dataclass
class RefslotData:
    available: bool
    withdrawalVaultBalance: uint256
    elRewardsVaultBalance: uint256
    sharesRequestedToBurn: uint256


@dataclass
class ExtraDataItem:
    index: uint24
    item_type: uint16
    module_id: uint24
    node_ops_count: uint64
    node_op_ids: list[uint64]
    # for item_type=1: stuckValidatorsCounts
    # for item_type=2: exitedValidatorsCounts
    validators_counts: list[uint64]

    @property
    def sorting_key(self) -> tuple[int, ...]:
        return (self.item_type, self.module_id, *self.node_op_ids[:8])

    def __bytes__(self) -> bytes:
        return (
            self.index.to_bytes(3, "big")
            + self.item_type.to_bytes(2, "big")
            + self.module_id.to_bytes(3, "big")
            + self.node_ops_count.to_bytes(8, "big")
            + b"".join(map(lambda v: int.to_bytes(v, 8, "big"), self.node_op_ids))
            + b"".join(
                map(lambda v: int.to_bytes(v, 16, "big"), self.validators_counts)
            )
        )

    def keccak_hash(self) -> bytes32:
        return keccak256(bytes(self))


@dataclass
class ExtraDataChunk:
    next_hash: bytes32
    items: list[ExtraDataItem]

    def __bytes__(self) -> bytes:
        return self.next_hash + b"".join(map(bytes, self.items))

    def keccak_hash(self) -> bytes32:
        return keccak256(bytes(self))


@dataclass
class VEBOData:
    module_id: uint24
    node_id: uint40
    validator_index: uint64
    public_key: bytes

    def __bytes__(self) -> bytes:
        assert len(self.public_key) == 48
        return (
            self.module_id.to_bytes(3, "big")
            + self.node_id.to_bytes(5, "big")
            + self.validator_index.to_bytes(8, "big")
            + self.public_key
        )


@dataclass
class ExtraSubmissionState:
    complete: bool
    extra_data_chunk: List[ExtraDataChunk]
    submit_index: int


@dataclass
class LidoBeaconState:
    deposited_validators: int
    beacon_validators: int
    beacon_balance: int


# initial values
PAUSE_INTENT_VALIDITY_PERIOD_BLOCKS = 10
MAX_OPERATORS_PER_UNVETTING = 10
STUCK_PENALTY_DELAY = 2 * 24 * 60 * 60


class LidoFuzzTest(CsmFuzzTest):
    # parameters
    config: LidoLocator.Config
    withdrawal_credentials: bytes32
    dsm_quorum: uint
    dsm_paused: bool

    # actors
    admin: Account
    no_manager: Account
    no_limiter: Account
    sr_module_manager: Account
    sr_rewards_reporter: Account
    sr_unsafe_role: Account
    sr_unvetting_role: Account
    dsm_guardians: List[Account]
    quaram_member: Account
    report_submitter: Account

    # components
    lib: MinFirstAllocationStrategy
    sr: StakingRouter
    dsm: DepositSecurityModule
    nors: Dict[int, NodeOperatorsRegistryMigrated]
    nor_ids: OrderedSet[int]
    staking_modules: Dict[int, StakingModule]
    deployed_staking_modules: Dict[int, IStakingModule]
    ao: AccountingOracle
    hc_ao: HashConsensus  # HashConsensus for AccountingOracle
    vebo: ValidatorsExitBusOracle  # ValidatorsExitBusOracle
    hc_vebo: HashConsensus  # HashConsensus for ValidatorExitBusOracle
    beacon_chain: BeaconChain
    sanity_ckecker: OracleReportSanityChecker

    withdraw_request_ids: Dict[int, List[uint256]]
    finalized_withdraw_request_ids: List[uint256]
    withdraw_request_owner: Dict[uint256, Account]

    # report data
    main_report_sumission: Dict[int, bool]  # report submission for accounting oracle
    vebo_report_submission: Dict[int, bool]
    refslot_data: Dict[int, RefslotData]
    deposited_inc_in_frame: Dict[int, uint256]
    wq_is_bunker_mode: bool

    lido_beacon_state: LidoBeaconState

    extra_data_submission_state: Dict[int, ExtraSubmissionState]

    def pre_sequence(self) -> None:
        super().pre_sequence()
        logger.info("== NEW SEQUENCE INITIATED ===")
        self.lib = MinFirstAllocationStrategy.deploy()

        self.wq_is_bunker_mode = False
        # set parameters
        self.config = FORK_CONFIG
        self.withdrawal_credentials = random_bytes(32)
        self.dsm_paused = False
        self.dsm_quorum = 0

        # set actors
        self.admin = chain.accounts[0]
        self.no_manager = chain.accounts[1]
        self.no_limiter = chain.accounts[2]
        self.sr_module_manager = chain.accounts[3]
        self.sr_rewards_reporter = chain.accounts[4]
        self.sr_exited_validators_reporter = chain.accounts[5]
        self.sr_unsafe_role = chain.accounts[6]
        self.sr_unvetting_role = chain.accounts[7]
        self.dsm_guardians = []
        self.staking_modules = {}

        self.quaram_member = chain.accounts[8]
        self.report_submitter = chain.accounts[9]

        self.withdraw_request_ids = {}
        self.withdraw_request_owner = {}
        self.finalized_withdraw_request_ids = []
        self.main_report_sumission = {}
        self.vebo_report_submission = {}
        self.refslot_data = {}
        self.deposited_inc_in_frame = {}
        self.nor_ids = OrderedSet()
        self.nors = {}
        self.deployed_staking_modules = {}
        self.extra_data_submission_state = {}

        (depositedValidators, beaconValidators, beaconBalance) = LIDO.getBeaconStat()

        self.lido_beacon_state = LidoBeaconState(
            deposited_validators=depositedValidators,
            beacon_validators=beaconValidators,
            beacon_balance=beaconBalance,
        )

        for i in range(10):
            self.withdraw_request_ids[i] = []

        # set components
        self.sr = deploy_staking_router(
            self.admin,
            self.sr_module_manager,
            self.sr_rewards_reporter,
            self.sr_exited_validators_reporter,
            self.sr_unsafe_role,
            self.sr_unvetting_role,
            DEPOSIT_CONTRACT,
            self.withdrawal_credentials,
            LIDO,
        )
        self.config.stakingRouter = self.sr

        self.dsm = deploy_deposit_security_module(
            self.admin,
            LIDO,
            DEPOSIT_CONTRACT,
            self.sr,
            PAUSE_INTENT_VALIDITY_PERIOD_BLOCKS,
            MAX_OPERATORS_PER_UNVETTING,
        )
        self.config.depositSecurityModule = self.dsm

        self.sr.grantRole(self.sr.STAKING_MODULE_UNVETTING_ROLE(), self.dsm)

        # deploy oracle
        self.beacon_chain = BeaconChain(
            chain,
        )

        self.ao = deploy_accounting_oracle(
            self.admin, self.report_submitter, self.beacon_chain
        )
        self.config.accountingOracle = self.ao

        self.hc_ao = deploy_hash_consensus(
            self.ao, self.quaram_member, self.admin, self.beacon_chain
        )
        initialEpoch = (
            ILegacyOracle(LEGACY_ORACLE).getLastCompletedEpochId()
            + self.beacon_chain.EPOCHS_PER_FRAME
        )
        self.hc_ao.updateInitialEpoch(initialEpoch)

        self.beacon_chain.INITIAL_EPOCH = initialEpoch

        self.ao.initialize(
            admin=self.admin,
            consensusContract=self.hc_ao,
            consensusVersion=2,
        )

        # submitter config
        self.ao.grantRole(
            self.ao.SUBMIT_DATA_ROLE(), self.report_submitter, from_=self.admin
        )

        # legacy oracle ao overwrite
        chain.chain_interface.set_storage_at(
            str(LEGACY_ORACLE.address),
            int.from_bytes(keccak256(b"lido.LidoOracle.accountingOracle")),
            int.from_bytes(bytes(self.ao.address)).to_bytes(32, "big"),
        )
        ret = LEGACY_ORACLE.call(abi.encode_with_signature("getAccountingOracle()"))
        ret_address = Address("0x" + ret[12:32].hex())
        assert ret_address == self.ao.address

        self.vebo = deploy_validator_exit_bus_oracle(self.admin, self.report_submitter)
        self.config.validatorsExitBusOracle = self.vebo

        self.hc_vebo = deploy_hash_consensus(
            self.vebo, self.quaram_member, self.admin, self.beacon_chain
        )

        initialEpoch = self.beacon_chain.current_epoch
        self.hc_vebo.updateInitialEpoch(initialEpoch)

        self.vebo.initialize(
            admin=self.admin,
            consensusContract=self.hc_vebo,
            consensusVersion=2,
            lastProcessingRefSlot=self.beacon_chain.current_epoch,
        )

        # submitter role config
        self.vebo.grantRole(
            self.vebo.SUBMIT_DATA_ROLE(), self.report_submitter, from_=self.admin
        )

        # resume role config
        self.vebo.grantRole(self.vebo.RESUME_ROLE(), self.admin, from_=self.admin)

        # OracleReportSanityChecker deploy
        limit_list = LimitsList(
            exitedValidatorsPerDayLimit=1000,
            appearedValidatorsPerDayLimit=1000,
            annualBalanceIncreaseBPLimit=10000,
            simulatedShareRateDeviationBPLimit=10000,
            maxValidatorExitRequestsPerReport=1000,
            maxItemsPerExtraDataTransaction=1000,
            maxNodeOperatorsPerExtraDataItem=1000,
            requestTimestampMargin=0,
            maxPositiveTokenRebase=1000000,
            initialSlashingAmountPWei=1000,
            inactivityPenaltiesAmountPWei=1000,
            clBalanceOraclesErrorUpperBPLimit=1000,
        )
        self.sanity_ckecker = OracleReportSanityChecker.deploy(
            LIDO_LOCATOR, self.admin, limit_list
        )
        self.config.oracleReportSanityChecker = self.sanity_ckecker

        # resume vebo
        self.vebo.resume(
            from_=self.admin
        )  # RESUME_ROLE() role set to admin manually while deploying

        if DEPLOY_WQ:
            self.withdrawal_queue = WithdrawalQueueERC721(
                OssifiableProxy.deploy(
                    WithdrawalQueueERC721.deploy(
                        WST_ETH, "Lido: stETH Withdrawal NFT", "unstETH"
                    ),
                    self.admin,
                    b"",
                )
            )
            self.withdrawal_queue.initialize(self.admin)
            self.withdrawal_queue.grantRole(
                self.withdrawal_queue.ORACLE_ROLE(), self.ao
            )
            self.withdrawal_queue.grantRole(
                self.withdrawal_queue.RESUME_ROLE(), self.admin
            )
            assert True == self.withdrawal_queue.hasRole(
                self.withdrawal_queue.ORACLE_ROLE(), self.ao
            )
            self.config.withdrawalQueue = self.withdrawal_queue
            LIDO.approve(BURNER, 2**256 - 1, from_=self.withdrawal_queue)
            self.withdrawal_queue.resume(from_=self.admin)
            self.withdrawal_queue.grantRole(self.withdrawal_queue.FINALIZE_ROLE(), LIDO)
        else:
            # change WithdrawQueue config
            access_control_overwrite(
                WITHDRAWAL_QUEUE, WITHDRAWAL_QUEUE.ORACLE_ROLE(), self.ao
            )
            self.withdrawal_queue = WITHDRAWAL_QUEUE

        self.sr.grantRole(
            self.sr.REPORT_EXITED_VALIDATORS_ROLE(), self.ao, from_=self.admin
        )

        # update locator
        OssifiableProxy(LIDO_LOCATOR).proxy__changeAdmin(
            self.admin, from_=Address("0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c")
        )
        update_locator(self.admin, self.config)

        for acc in [
            WITHDRAWAL_VAULT,
            LIDO,
            self.sr,
            self.dsm,
        ]:  # EL_REWARDS_VAULT set in csm
            self.balances[acc] = acc.balance
            self.shares[acc] = LIDO.sharesOf(acc)

        self.main_report_sumission[self.beacon_chain.current_frame_index] = True

    def post_invariants(self) -> None:
        return super().post_invariants()

    """
        Helper functions
    """

    def get_staking_module_id(self) -> int:
        return random_int(1, len(self.staking_modules))

    def update_summary_max_validators_count(
        self, no: NodeOperator, staking_module_id: int
    ) -> None:
        new_max_keys_count = no.vetted_keys_count

        if staking_module_id in self.nor_ids and not self.nors[
            staking_module_id
        ].isOperatorPenaltyCleared(no.id):
            new_max_keys_count = no.deposited_keys_count
        elif no.target_limit_mode != 0:
            new_max_keys_count = max(
                no.deposited_keys_count,
                min(new_max_keys_count, no.exited_keys_count + no.target_limit),
            )

        old_max_keys_count = no.max_keys_count
        if old_max_keys_count != new_max_keys_count:
            no.max_keys_count = new_max_keys_count

        if old_max_keys_count == new_max_keys_count:
            return
        elif new_max_keys_count > old_max_keys_count:
            no.summary_max_keys_count += new_max_keys_count
        else:
            no.summary_max_keys_count -= new_max_keys_count

        self.staking_modules[staking_module_id].total_depostable_keys_count += (
            new_max_keys_count - old_max_keys_count
        )

    def invalidate_ready_to_deposit_keys_range(
        self,
        index_from: uint,
        index_to: uint,
        nos: List[NodeOperator],
        staking_module_id: int,
    ) -> None:
        trimmed_keys_count = 0
        for no in nos:
            if no.id in range(index_from, index_to + 1):
                if no.total_keys_count != no.deposited_keys_count:
                    trimmed_keys_count += no.total_keys_count - no.deposited_keys_count
                    no.total_keys_count = no.deposited_keys_count
                    no.vetted_keys_count = no.deposited_keys_count
                    self.update_summary_max_validators_count(no, staking_module_id)

                    no.keys = no.keys[: no.total_keys_count]

        return trimmed_keys_count

    def random_node_operators_and_keys_count(
        self, type: str, nos: List[NodeOperator]
    ) -> Tuple[bytes, bytes, List[NodeOperator], List[int]]:
        no_len = random_int(1, len(nos))
        nors = random.choices(nos, k=no_len)

        node_operator_ids_encoded = b"".join([uint64(no.id).to_bytes(8, "big") for no in nors])
        new_keys_counts = []
        if type == "vetted":
            new_keys_counts = [
                uint128(random_int(0, no.total_keys_count)) for no in nors
            ]
        elif type == "stucked":
            new_keys_counts = [
                uint128(random_int(0, no.deposited_keys_count - no.exited_keys_count))
                for no in nors
            ]
        elif type == "exited":
            new_keys_counts = [
                uint128(random_int(0, no.deposited_keys_count - no.stuck_keys_count))
                for no in nors
            ]

        new_keys_count_encoded = b"".join([uint128(count).to_bytes(16, "big") for count in new_keys_counts])

        return (
            node_operator_ids_encoded,
            new_keys_count_encoded,
            nors,
            new_keys_counts,
        )

    def random_node_operators_and_keys_count_array(
        self, type: str, nos_dict: Dict[int, NodeOperator]
    ) -> Tuple[List[NodeOperator], List[int], List[int]]:
        # Ensure nos is sorted by id to maintain order
        nos = list(nos_dict.values())
        nos.sort(key=lambda no: no.id)

        no_len = random.randint(
            1, len(nos)
        )  # Get a random number of NodeOperators to select
        nors = random.sample(
            nos, k=no_len
        )  # Select them without collision (no duplicates)

        # Sort the selected sample by id again to ensure order
        nors.sort(key=lambda no: no.id)

        ids = [uint64(no.id) for no in nors]
        new_keys_counts = []
        if type == "vetted":
            new_keys_counts = [
                uint128(random_int(0, no.total_keys_count)) for no in nors
            ]
        elif type == "stucked":
            new_keys_counts = [
                uint128(
                    random_int(
                        no.exited_keys_count,
                    )
                )
                for no in nors
            ]
        elif type == "exited":
            new_keys_counts = [
                uint128(random_int(no.exited_keys_count, no.deposited_keys_count))
                for no in nors
            ]
        elif type == "exit_request":
            new_keys_counts = []
            for no in nors:
                new_keys_counts.append(
                    uint128(no.exit_requested_key_count)
                )  # one by one
        return (nors, ids, new_keys_counts)

    def random_node_operators_and_keys_count_array_for_stuck(
        self, nos_dict: Dict[int, NodeOperator]
    ) -> Tuple[List[NodeOperator], List[int], List[int], Dict[int, int]]:
        # Ensure nos is sorted by id to maintain order
        nos = list(nos_dict.values())
        nos.sort(key=lambda no: no.id)
        no_len = random.randint(1, len(nos))
        selected_nos = random.sample(nos, k=no_len)
        selected_nos.sort(key=lambda no: no.id)
        ids = [uint64(no.id) for no in selected_nos]

        stuck_temp = {}
        new_stucked_key_counts = []
        for no in selected_nos:

            stuck_temp[no.id] = random_int(
                0, no.deposited_keys_count - no.exited_keys_count
            )
            new_stucked_key_counts.append(uint128(stuck_temp[no.id]))

        return (selected_nos, ids, new_stucked_key_counts, stuck_temp)

    def random_node_operators_and_keys_count_array_for_exit(
        self, nos_dict: Dict[int, NodeOperator], stuck_temp: Dict[int, int]
    ) -> Tuple[List[NodeOperator], List[int], List[int]]:
        # Ensure nos is sorted by id to maintain order
        nos = list(nos_dict.values())
        nos.sort(key=lambda no: no.id)
        no_len = random.randint(1, len(nos))
        nors = random.sample(nos, k=no_len)
        nors.sort(key=lambda no: no.id)
        ids = [uint64(no.id) for no in nors]

        new_exited_key_counts = []
        filtered_nors = []
        filtered_ids = []

        new_exited_key_counts = []
        for no in nors:
            if no.id in stuck_temp.keys():
                if no.exited_keys_count > no.deposited_keys_count - stuck_temp[no.id]:
                    continue
                new_exited_key_counts.append(
                    random_int(
                        no.exited_keys_count,
                        no.deposited_keys_count - stuck_temp[no.id],
                    )
                )
                filtered_nors.append(no)
                filtered_ids.append(no.id)
            else:
                if no.exited_keys_count > no.deposited_keys_count - no.stuck_keys_count:
                    continue
                new_exited_key_counts.append(
                    random_int(
                        no.exited_keys_count,
                        no.deposited_keys_count - no.stuck_keys_count,
                    )
                )
                filtered_nors.append(no)
                filtered_ids.append(no.id)

        return (filtered_nors, filtered_ids, new_exited_key_counts)

    def min_allocation(
        self,
        allocations: List[uint256],
        capacities: List[uint256],
        max_allocation_size: uint256,
    ) -> Tuple[uint256, List[uint256]]:
        assert len(allocations) == len(capacities)
        allocated_count = 0
        for i in range(max_allocation_size):
            min_allocated = uint256.max
            min_allocated_index = -1
            for j in range(len(allocations)):
                if allocations[j] >= capacities[j]:
                    continue
                if (
                    allocations[j] < min_allocated
                ):  # if same, min index will be selected
                    min_allocated = allocations[j]
                    min_allocated_index = j

            if min_allocated_index == -1:  # there is no possible allocation
                break

            allocations[min_allocated_index] += 1
            allocated_count += 1

        return allocated_count

    def add_csm_depositable_keys(self, id, count):
        self.staking_modules[id].total_depostable_keys_count += count

    def add_deposited_keys(self, id, count):
        self.staking_modules[id].total_deposited_keys_count += count

    def add_csm_active_no(self, id):
        self.staking_modules[id].active_node_operators += 1

    def sub_csm_depositable_keys(self, id, count):
        self.staking_modules[id].total_depostable_keys_count -= count

    def add_csm_beacon_deposited_keys(self, count):
        self.lido_beacon_state.deposited_validators += count

    """
        Staking Router flows
    """

    #
    # Function:     addStakingModule with deploy staking module (NOR or CSM)
    # Caller:       sr_module_manager
    # Description:  Add staking module, randomly select NOR or CSM
    # Status:       Done
    #
    @flow(max_times=MAX_STAKING_MODULES_COUNT)
    def set_staking_module(self) -> None:
        self.invariant_balances()
        stake_share_limit = random_int(0, TOTAL_BASIS_POINTS, max_prob=0.5)
        priority_exit_share_threshold = random_int(
            stake_share_limit, TOTAL_BASIS_POINTS
        )
        staking_module_fee = random_int(0, 1_000)  # max up to 10%
        treasury_fee = random_int(0, 1_000)  # max up to 10%

        min_deposit_block_distance = random_int(1, 10)
        max_deposits_per_block = random_int(0, 100)

        staking_modules_count = self.sr.getStakingModulesCount()
        assert staking_modules_count == len(self.staking_modules)
        is_csm = False
        id = staking_modules_count + 1

        module = None
        if random_bool():
            if CSM_MAX_COUNT > len(self.csms):
                module = self.add_csm(id)
                is_csm = True
            else:
                if NOR_MAX_COUNT <= len(self.nors):
                    return
                module = deploy_node_operator_registry(
                    self.lib,
                    self.no_manager,
                    self.no_limiter,
                    self.sr,
                    STUCK_PENALTY_DELAY,
                    TEST_OLD_SOLIDITY,
                    appId("node-operators-registry", staking_modules_count),
                )
                is_csm = False
        else:
            if NOR_MAX_COUNT > len(self.nors):
                # deploy csm
                module = deploy_node_operator_registry(
                    self.lib,
                    self.no_manager,
                    self.no_limiter,
                    self.sr,
                    STUCK_PENALTY_DELAY,
                    TEST_OLD_SOLIDITY,
                    appId("node-operators-registry", staking_modules_count),
                )
                is_csm = False
            else:
                if CSM_MAX_COUNT <= len(self.csms):
                    return
                module = self.add_csm(id)
                is_csm = True

        self.balances[module] = module.balance
        self.shares[module] = LIDO.sharesOf(module)

        tx = self.sr.addStakingModule(
            _name="NOR - Curated staking module",
            _stakingModuleAddress=module,
            _stakeShareLimit=stake_share_limit,
            _priorityExitShareThreshold=priority_exit_share_threshold,
            _stakingModuleFee=staking_module_fee,
            _treasuryFee=treasury_fee,
            _maxDepositsPerBlock=max_deposits_per_block,
            _minDepositBlockDistance=min_deposit_block_distance,
            from_=self.sr_module_manager,
        )

        self.deployed_staking_modules[id] = IStakingModule(module)
        self.staking_modules[id] = StakingModule(
            id=id,
            nonce=0,
            node_operators={},
            staking_module=self.sr.getStakingModule(id),
            total_exited_keys_count=0,
            total_exited_keys_count_in_sr=0,
            total_deposited_keys_count=0,
            max_deposits_per_block=max_deposits_per_block,
            total_depostable_keys_count=0,
            stake_share_limit=stake_share_limit,
            reward_distribution_state=NodeOperatorsRegistryMigrated.RewardDistributionState.Distributed,
            active_node_operators=0,
            stuck_penalty_delay=STUCK_PENALTY_DELAY,
            staking_module_fee=staking_module_fee,
            treasury_fee=treasury_fee,
            is_csm=is_csm,
        )

        if not is_csm:
            self.nor_ids.add(id)
            self.nors[id] = module

        for e in tx.events:
            if isinstance(e, StakingRouter.StakingModuleShareLimitSet):
                assert e.stakingModuleId == id
                assert e.stakeShareLimit == stake_share_limit
                assert e.priorityExitShareThreshold == priority_exit_share_threshold
                assert e.setBy == self.sr_module_manager.address
            elif isinstance(e, StakingRouter.StakingModuleFeesSet):
                assert e.stakingModuleFee == staking_module_fee
                assert e.treasuryFee == treasury_fee
            elif isinstance(e, StakingRouter.StakingModuleMaxDepositsPerBlockSet):
                assert e.maxDepositsPerBlock == max_deposits_per_block
            elif isinstance(e, StakingRouter.StakingModuleMinDepositBlockDistanceSet):
                assert e.minDepositBlockDistance == min_deposit_block_distance

        assert self.sr.getStakingModulesCount() == staking_modules_count + 1
        assert self.sr.hasStakingModule(id) == True
        assert (
            self.sr.getStakingModuleStatus(id)
            == StakingRouter.StakingModuleStatus.Active
        )
        assert self.sr.getStakingModuleActiveValidatorsCount(id) == 0
        assert self.sr.getStakingModuleNonce(id) == 0
        assert (
            self.sr.getStakingModuleLastDepositBlock(id)
            == chain.blocks["latest"].number
        )

        logger.info(f"Added staking module {id}")

    #
    # Function:     updateStakingModule
    # Caller:       sr_module_manager
    # Description:  Updates an existing staking module (except NOR), no state change in the staking module
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_update_staking_module(self) -> None:
        stake_share_limit = random_int(0, TOTAL_BASIS_POINTS)
        priority_exit_share_threshold = random_int(
            stake_share_limit, TOTAL_BASIS_POINTS
        )
        staking_module_fee = random_int(0, 1_000)  # max up to 10%
        treasury_fee = random_int(0, 1_000)  # max up to 10%
        min_deposit_block_distance = random_int(1, 10)
        max_deposits_per_block = random_int(0, 100)

        staking_modules_count = self.sr.getStakingModulesCount()
        assert staking_modules_count == len(self.staking_modules)
        id = random_int(1, staking_modules_count)

        tx = self.sr.updateStakingModule(
            _stakingModuleId=id,
            _stakeShareLimit=stake_share_limit,
            _priorityExitShareThreshold=priority_exit_share_threshold,
            _stakingModuleFee=staking_module_fee,
            _treasuryFee=treasury_fee,
            _maxDepositsPerBlock=max_deposits_per_block,
            _minDepositBlockDistance=min_deposit_block_distance,
            from_=self.sr_module_manager,
        )

        self.staking_modules[id].staking_module = self.sr.getStakingModule(id)
        self.staking_modules[id].stake_share_limit = stake_share_limit
        self.staking_modules[id].staking_module_fee = staking_module_fee
        self.staking_modules[id].treasury_fee = treasury_fee

        for e in tx.events:
            if isinstance(e, StakingRouter.StakingModuleShareLimitSet):
                assert e.stakingModuleId == id
                assert e.stakeShareLimit == stake_share_limit
                assert e.priorityExitShareThreshold == priority_exit_share_threshold
                assert e.setBy == self.sr_module_manager.address
            elif isinstance(e, StakingRouter.StakingModuleFeesSet):
                assert e.stakingModuleFee == staking_module_fee
                assert e.treasuryFee == treasury_fee
            elif isinstance(e, StakingRouter.StakingModuleMaxDepositsPerBlockSet):
                assert e.maxDepositsPerBlock == max_deposits_per_block
            elif isinstance(e, StakingRouter.StakingModuleMinDepositBlockDistanceSet):
                assert e.minDepositBlockDistance == min_deposit_block_distance

        self.staking_modules[id].max_deposits_per_block = max_deposits_per_block

        assert self.sr.getStakingModulesCount() == staking_modules_count
        logger.info(f"Updated staking module {id}")

    #
    # Function:     updateTargetValidatorsLimits
    # Caller:       sr_module_manager
    # Description:  Updates target validators limits for ONE staking module and ONE node operator (max validators that can be used for deposit)
    #
    # Status:       DONE
    #
    @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_update_target_validators_limits(self) -> None:
        staking_module_id = self.get_staking_module_id()
        is_csm = False
        if staking_module_id in self.nor_ids:
            nos = self.staking_modules[staking_module_id].node_operators
            if len(nos) == 0:
                logger.info(f"Empty NOS")
                return
        else:
            is_csm = True
            nos = self.csms[staking_module_id].node_operators
            if len(nos) == 0:
                logger.info(f"Empty NOS")
                return
        no = random.choice(list(nos.values()))
        depositable_before = None
        if is_csm:
            depositable_before = self._get_depositable_keys(
                self.csms[staking_module_id].node_operators[no.id],
                chain.blocks["latest"].timestamp,
            )

            depositable_before_contract = (
                self.csms[staking_module_id]
                .module.getNodeOperator(no.id)
                .depositableValidatorsCount
            )
            assert depositable_before == depositable_before_contract
        if random_bool():
            if is_csm:
                new_target_validators_count = random_int(0, 2**32 - 1)
            else:
                new_target_validators_count = random_int(0, 2**64 - 1)
        else:
            new_target_validators_count = random_int(0, 50)

        mode = random_int(0, 2)

        tx = self.sr.updateTargetValidatorsLimits(
            _stakingModuleId=staking_module_id,
            _nodeOperatorId=no.id,
            _targetLimitMode=mode,
            _targetLimit=new_target_validators_count,
            from_=self.sr_module_manager,
        )

        if mode == 0:
            new_target_validators_count = 0

        if is_csm:
            if (
                no.target_limit_mode != mode
                or no.target_limit != new_target_validators_count
            ):
                no.target_limit_mode = mode
                no.target_limit = new_target_validators_count

                assert depositable_before is not None
                # nonce update done in reenqueue
                self._reenqueue(self.csms[staking_module_id], no.id, depositable_before)
                assert (
                    CSModule.TargetValidatorsCountChanged(
                        no.id, mode, new_target_validators_count
                    )
                    in tx.events
                )
                self.csms[staking_module_id].nonce += 1
                assert (
                    CSModule.NonceChanged(self.csms[staking_module_id].nonce)
                    in tx.events
                )

                assert (
                    self._get_enqueued_keys(self.csms[staking_module_id], no.id)
                    == self.csms[staking_module_id]
                    .module.getNodeOperator(no.id)
                    .enqueuedCount
                )
            else:
                assert not any(
                    e
                    for e in tx.events
                    if isinstance(e, CSModule.TargetValidatorsCountChanged)
                )
                assert not any(
                    e for e in tx.events if isinstance(e, CSModule.NonceChanged)
                )
        else:
            no.target_limit_mode = mode
            no.target_limit = new_target_validators_count

            self.update_summary_max_validators_count(no, staking_module_id)
            self.staking_modules[staking_module_id].nonce += 1
        logger.info(
            f"Updated target validators limits for staking module {staking_module_id} and node operator {no.id} with mode: {mode} and limit: {no.target_limit}"
        )

    #
    # Function:     updateRefundedValidatorsCount
    # Caller:       sr_module_manager
    # Description:  Updates refunded validators count for ONE staking module and ONE node operator
    # Status:       Done
    #
    @flow(
        precondition=lambda self: len(self.staking_modules) > 0
        and USE_UPDATE_REFUNDED == True
    )
    def flow_update_refunded_validators_count(self) -> None:
        staking_module_id = self.get_staking_module_id()
        if staking_module_id in self.nor_ids:
            nos = self.staking_modules[staking_module_id].node_operators
            if len(nos) == 0:
                logger.info(f"Empty NOS")
                return
        else:  # CSM
            nos = self.csms[staking_module_id].node_operators
            if len(nos) == 0:
                logger.info(f"Empty NOS")
                return

            no = random.choice(list(nos.values()))
            new_refunded_keys_count = random_int(0, no.deposited_keys_count)

            with must_revert(CSModule.NotSupported()):
                tx = self.sr.updateRefundedValidatorsCount(
                    _stakingModuleId=staking_module_id,
                    _nodeOperatorId=no.id,
                    _refundedValidatorsCount=new_refunded_keys_count,
                    from_=self.sr_module_manager,
                )
            return

        no = random.choice(list(nos.values()))
        new_refunded_keys_count = random_int(0, no.deposited_keys_count)

        if no.deposited_keys_count == no.refunded_keys_count:
            new_refunded_keys_count = no.refunded_keys_count
        else:
            new_refunded_keys_count = random_int(
                no.refunded_keys_count, no.deposited_keys_count, max_prob=0.9
            )

        tx = self.sr.updateRefundedValidatorsCount(
            _stakingModuleId=staking_module_id,
            _nodeOperatorId=no.id,
            _refundedValidatorsCount=new_refunded_keys_count,
            from_=self.sr_module_manager,
        )
        event = next(
            (
                e
                for e in tx.events
                if isinstance(e, NodeOperatorsRegistryMigrated.StuckPenaltyStateChanged)
            ),
            None,
        )
        if no.refunded_keys_count == new_refunded_keys_count:
            assert event is None
        else:
            assert event is not None
            assert event.nodeOperatorId == no.id
            assert event.refundedValidatorsCount == new_refunded_keys_count
            if staking_module_id in self.nor_ids:
                if (
                    new_refunded_keys_count >= no.stuck_keys_count
                    and no.stuck_keys_count > no.refunded_keys_count
                ):
                    assert (
                        event.stuckPenaltyEndTimestamp
                        == chain.blocks["latest"].timestamp
                        + self.staking_modules[staking_module_id].stuck_penalty_delay
                    )
                no.stuck_penalty_end_timestamp = event.stuckPenaltyEndTimestamp

            no.refunded_keys_count = new_refunded_keys_count
            self.update_summary_max_validators_count(no, staking_module_id)
            logger.info(
                f"Updated refunded validators count for staking module {staking_module_id}"
            )

        self.staking_modules[staking_module_id].nonce += 1

    #
    # Function:     reportRewardsMinted
    # Caller:       sr_rewards_reporter
    # Description:  Calls `onRewardsMinted()` on chosen staking modules
    #               Unflow since it is called by LIDO, for NOR
    # Status:       Done
    #
    # @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_report_rewards_minted(self) -> None:
        number_of_modules_to_update = random_int(1, len(self.staking_modules))
        staking_module_ids = random.sample(
            list(self.staking_modules.keys()), number_of_modules_to_update
        )
        total_shares = [
            random_int(0, 1_000) for _ in range(number_of_modules_to_update)
        ]

        self.sr.reportRewardsMinted(
            _stakingModuleIds=staking_module_ids,
            _totalShares=total_shares,
            from_=self.sr_rewards_reporter,
        )
        logger.info(
            f"Reported rewards minted for {number_of_modules_to_update} staking modules"
        )

    #
    # Function:     updateExitedValidatorsCountByStakingModule
    # Caller:       sr_exited_validators_reporter called by accounting oracle
    # Description:  Updates total count of exited validators for staking modules with the specified module ids
    #               Unflow since it is called by Accounting Oracle
    #               Nor count does not changes, Individual call makes inconsistency in the data, if it happen, it can fix by unsafe function
    # Status:       Done
    #
    # @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_update_exited_validators_count_by_staking_module(self) -> None:
        staking_module_ids = []
        exited_validator_counts = []
        for id in self.staking_modules.keys():
            if random_bool():
                sm = self.sr.getStakingModule(id)
                exited, deposited, _ = IStakingModule(
                    sm.stakingModuleAddress
                ).getStakingModuleSummary()
                if exited == 0 and deposited == 0:
                    continue
                try:
                    exited_validator_count = random_int(exited, deposited)
                except:
                    logger.info(f"Can not exit more validators than deposited")
                    return
                staking_module_ids.append(id)
                exited_validator_counts.append(exited_validator_count)

        with may_revert() as e:
            tx = self.sr.updateExitedValidatorsCountByStakingModule(
                _stakingModuleIds=staking_module_ids,
                _exitedValidatorsCounts=exited_validator_counts,
                from_=self.sr_exited_validators_reporter,
            )
        is_exit_count_decreased = False
        is_exit_exceed_deposited = False
        for i in range(len(staking_module_ids)):
            if (
                exited_validator_counts[i]
                < self.sr.getStakingModule(staking_module_ids[i]).exitedValidatorsCount
            ):
                is_exit_count_decreased = True
                break
            if (
                exited_validator_counts[i]
                > self.staking_modules[staking_module_ids[i]].total_deposited_keys_count
            ):
                is_exit_exceed_deposited = True
                break

        if is_exit_count_decreased:
            assert e.value == StakingRouter.ExitedValidatorsCountCannotDecrease()
            return

        if is_exit_exceed_deposited:
            assert e.value == StakingRouter.ReportedExitedValidatorsExceedDeposited()
            return

        assert e.value is None
        logger.info(
            f"Updated exited validators count for {len(staking_module_ids)} staking modules"
        )

    #
    # Function:     reportStakingModuleExitedValidatorsCountByNodeOperator
    # Caller:       sr_exited_validators_reporter
    # Description:  Updates count of exited validators for ONE staking module and MANY node operators
    #               Same as above flow those two flow should be called by accounting oracle not in one transaction but called with sync.
    #               Unflow since it is called by Staking router
    # Status:       Done
    #
    # @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_update_exited_validators_count(self) -> None:
        staking_module_id = self.get_staking_module_id()
        nos = self.staking_modules[staking_module_id].node_operators
        if len(nos) == 0:
            logger.info(f"Empty NOS")
            return
        no_ids_encoded, keys_encoded, sel_no, key_counts = (
            self.random_node_operators_and_keys_count("exited", nos)
        )

        events = []
        with may_revert(("EXITED_VALIDATORS_COUNT_DECREASED")) as e:
            tx = self.sr.reportStakingModuleExitedValidatorsCountByNodeOperator(
                _stakingModuleId=staking_module_id,
                _nodeOperatorIds=no_ids_encoded,
                _exitedValidatorsCounts=keys_encoded,
                from_=self.sr_exited_validators_reporter,
            )

            events = [
                e
                for e in tx.events
                if isinstance(
                    e, NodeOperatorsRegistryMigrated.ExitedSigningKeysCountChanged
                )
            ]

        is_revert = False
        temp_counter = {}
        for i in range(len(sel_no)):
            no = sel_no[i]
            keys = key_counts[i]
            if temp_counter.get(no.id) is None:
                temp_counter[no.id] = no.exited_keys_count
                if no.exited_keys_count > keys:
                    is_revert = True
                    break
                else:
                    temp_counter[no.id] = keys
            else:
                if temp_counter[no.id] > keys:
                    is_revert = True
                    break
                else:
                    temp_counter[no.id] = keys

        if is_revert:
            assert e.value == Error("EXITED_VALIDATORS_COUNT_DECREASED")
            return

        # pre calculation for summary count
        nos_mapping = {}
        for i in range(len(sel_no)):
            no = sel_no[i]
            keys = key_counts[i]
            nos_mapping[no.id] = keys  # stored final key count

        changes_summary = 0
        if staking_module_id in self.nor_ids:  # if nor
            # this will positive value, should not decrease
            for id in nos_mapping.keys():
                changes_summary += (
                    nos_mapping[id]
                    - self.staking_modules[staking_module_id]
                    .node_operators[id]
                    .exited_keys_count
                )

        assert e.value == None
        event_smaller = 0
        num_events = len(events)
        for i in range(len(sel_no)):
            no = sel_no[i]
            keys = key_counts[i]
            prev_events = events
            event = next((e for e in events if e.nodeOperatorId == no.id), None)
            if event:
                found = False
                remaining_events = []
                for e in events:
                    if e.nodeOperatorId == no.id and not found:
                        found = True
                    else:
                        remaining_events.append(e)
                events = remaining_events

            if no.exited_keys_count == keys:
                # exist where event.nodeOperatorId == no.id
                if event is not None:
                    events = prev_events
                event_smaller += 1

            else:
                assert event is not None
                assert keys > no.exited_keys_count
                assert event.nodeOperatorId == no.id
                assert event.exitedValidatorsCount == keys
                no.exited_keys_count = keys
                self.update_summary_max_validators_count(no, staking_module_id)

        assert num_events + event_smaller == len(sel_no)

        if staking_module_id in self.nor_ids:  # if nor
            self.staking_modules[
                staking_module_id
            ].total_exited_keys_count += changes_summary

        self.staking_modules[staking_module_id].nonce += 1

        logger.info(
            f"Updated exited validators count for staking module {staking_module_id}!!å"
        )

    #
    # Function:     unsafeSetExitedValidatorsCount
    # Caller:       sr_unsafe_role
    # Description:  Flow that should be called rarely, corrects the state # only change staking module state!!!
    # Status:       DONE
    #
    @flow(
        precondition=lambda self: len(self.staking_modules) > 0 and CALL_UNSAFE == True
    )
    def flow_unsafe_set_exited_validators_count(self) -> None:
        staking_module_id = self.get_staking_module_id()
        nos = self.staking_modules[staking_module_id].node_operators
        if len(nos) == 0:
            logger.info(f"Empty NOS")
            return
        no = random.choice(list(nos.values()))
        trigger_update_finish = random_bool()

        new_stuck_keys_count = uint128(
            random_int(0, no.deposited_keys_count - no.exited_keys_count)
        )
        new_exited_keys_count = uint128(
            random_int(0, no.deposited_keys_count - new_stuck_keys_count)
        )

        sm_info = self.sr.getStakingModule(staking_module_id)
        newModuleExitedValidatorsCount = self.staking_modules[
            staking_module_id
        ].total_exited_keys_count + (new_exited_keys_count - no.exited_keys_count)

        prev_inconsistent_sr_total = sm_info.exitedValidatorsCount

        correction_config = StakingRouter.ValidatorsCountsCorrection(
            currentModuleExitedValidatorsCount=prev_inconsistent_sr_total,
            currentNodeOperatorExitedValidatorsCount=no.exited_keys_count,
            currentNodeOperatorStuckValidatorsCount=no.stuck_keys_count,
            newModuleExitedValidatorsCount=newModuleExitedValidatorsCount,
            newNodeOperatorExitedValidatorsCount=new_exited_keys_count,
            newNodeOperatorStuckValidatorsCount=new_stuck_keys_count,
        )

        tx = self.sr.unsafeSetExitedValidatorsCount(
            _stakingModuleId=staking_module_id,
            _nodeOperatorId=no.id,
            _triggerUpdateFinish=trigger_update_finish,
            _correction=correction_config,
            from_=self.sr_unsafe_role,
        )

        if trigger_update_finish:
            self.staking_modules[staking_module_id].reward_distribution_state = (
                NodeOperatorsRegistryMigrated.RewardDistributionState.ReadyForDistribution
            )

        if no.exited_keys_count < new_exited_keys_count:  # increased
            for i in range(no.exited_keys_count, new_exited_keys_count):
                no.keys[i].key_state = KeyState.Exited
        else:
            for i in range(new_exited_keys_count, no.exited_keys_count):
                no.keys[i].key_state = KeyState.Deposited

        if staking_module_id in self.nor_ids:
            if (
                new_stuck_keys_count <= no.refunded_keys_count
                and no.stuck_keys_count > no.refunded_keys_count
            ):
                no.stuck_penalty_end_timestamp = (
                    chain.blocks["latest"].timestamp
                    + self.staking_modules[staking_module_id].stuck_penalty_delay
                )

        no.stuck_keys_count = new_stuck_keys_count
        no.exited_keys_count = new_exited_keys_count
        self.staking_modules[staking_module_id].total_exited_keys_count = (
            newModuleExitedValidatorsCount
        )

        self.staking_modules[staking_module_id].total_exited_keys_count_in_sr = (
            newModuleExitedValidatorsCount
        )

        self.update_summary_max_validators_count(no, staking_module_id)

        self.staking_modules[staking_module_id].nonce += 1
        logger.info(f"Unsafe set exited validators count called!")

    #
    # Function:     reportStakingModuleStuckValidatorsCountByNodeOperator
    # Caller:       sr_exited_validators_reporter
    # Description:  Updates stuck validator count for ONE staking module and MANY node operators
    # Status:       Done
    #
    # @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_update_stuck_validators_count(self) -> None:
        staking_module_id = self.get_staking_module_id()
        nos = self.staking_modules[staking_module_id].node_operators
        if len(nos) == 0:
            logger.info(f"Empty NOS")
            return

        no_ids_encoded, new_keys_count_encoded, sel_no, key_counts = (
            self.random_node_operators_and_keys_count("stucked", nos)
        )

        tx = self.sr.reportStakingModuleStuckValidatorsCountByNodeOperator(
            _stakingModuleId=staking_module_id,
            _nodeOperatorIds=no_ids_encoded,
            _stuckValidatorsCounts=new_keys_count_encoded,
            from_=self.sr_exited_validators_reporter,
        )

        events = [
            e
            for e in tx.events
            if isinstance(e, NodeOperatorsRegistryMigrated.StuckPenaltyStateChanged)
        ]

        num_events = len(events)
        event_smaller = 0
        for i in range(len(sel_no)):
            no = sel_no[i]
            keys = key_counts[i]
            prev_events = events
            event = next((e for e in events if e.nodeOperatorId == no.id), None)
            if event:
                found = False
                remaining_events = []
                for e in events:
                    if e.nodeOperatorId == no.id and not found:
                        found = True  # Skip the first matching event
                    else:
                        remaining_events.append(e)
                events = remaining_events

            if no.stuck_keys_count == keys:
                if event is not None:
                    events = prev_events  # restore events
                event_smaller += 1
                # by default event is None but if 0110 sel_no and event is 110 this 0 will be takes as first event
            else:
                assert event is not None
                assert event.nodeOperatorId == no.id
                assert event.stuckValidatorsCount == keys
                assert event.refundedValidatorsCount == no.refunded_keys_count
                if staking_module_id in self.nor_ids:
                    if (
                        keys <= no.refunded_keys_count
                        and no.stuck_keys_count > no.refunded_keys_count
                    ):
                        assert (
                            event.stuckPenaltyEndTimestamp
                            == chain.blocks["latest"].timestamp
                            + self.staking_modules[
                                staking_module_id
                            ].stuck_penalty_delay
                        )
                        no.stuck_penalty_end_timestamp = event.stuckPenaltyEndTimestamp

                no.stuck_keys_count = keys  # only this changes
                self.update_summary_max_validators_count(no, staking_module_id)

        num_no = len(sel_no)

        assert num_no == num_events + event_smaller

        self.staking_modules[staking_module_id].nonce += 1
        logger.info(
            f"Updated stuck validators count for staking module {staking_module_id}"
        )

    #
    # Function:     onValidatorsCountsByNodeOperatorReportingFinished
    # Caller:       sr_exited_validators_reporter
    # Description:  Calls `onExitedAndStuckValidatorsCountsUpdated()` on ALL staking modules
    # Status:       Done
    #
    # @flow()
    def flow_on_validators_counts_by_node_operator_reporting_finished(self) -> None:
        self.sr.onValidatorsCountsByNodeOperatorReportingFinished(
            from_=self.sr_exited_validators_reporter
        )
        logger.info(f"On validators counts by node operator reporting finished!")

    #
    # Function:     decreaseStakingModuleVettedKeysCountByNodeOperator
    # Caller:       sr_unvetting_role, called by DSM only
    # Description:  Decreases vetted signing keys count on ONE staking module for MANY node operators
    #               called in flow_unvet_signing_keys flow so disabled
    # Status:       Done
    #
    # @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_decrease_vetted_keys_count(self) -> None:
        staking_module_id = self.get_staking_module_id()
        nos = self.staking_modules[staking_module_id].node_operators
        if len(nos) == 0:
            logger.info(f"Empty NOS")
            return
        (no_ids_encoded, keys_encoded, sel_no, key_counts) = (
            self.random_node_operators_and_keys_count("vetted", nos)
        )

        # not guarantee increase order
        events = []
        with may_revert() as e:
            tx = self.sr.decreaseStakingModuleVettedKeysCountByNodeOperator(
                _stakingModuleId=staking_module_id,
                _nodeOperatorIds=no_ids_encoded,
                _vettedSigningKeysCounts=keys_encoded,
                from_=self.sr_unvetting_role,
            )
            events = [
                e
                for e in tx.events
                if isinstance(
                    e, NodeOperatorsRegistryMigrated.VettedSigningKeysCountChanged
                )
            ]

        # the key must be linealy decreased even in a transaction
        is_revert = False
        temp_counter = {}
        for i in range(len(sel_no)):
            no = sel_no[i]
            keys = key_counts[i]

            keys_after = min(no.total_keys_count, max(keys, no.deposited_keys_count))
            if temp_counter.get(no.id) is None:
                temp_counter[no.id] = keys_after
                if no.vetted_keys_count < keys_after:
                    is_revert = True
                    break
                else:
                    temp_counter[no.id] = keys_after
            else:
                if temp_counter[no.id] < keys_after:
                    is_revert = True
                    break
                else:
                    temp_counter[no.id] = keys_after

        if is_revert:
            assert e.value == Error("VETTED_KEYS_COUNT_INCREASED")
            return

        num_event = len(events)
        event_smaller = 0
        assert e.value is None
        for i in range(len(sel_no)):
            no = sel_no[i]
            keys = key_counts[i]
            prev_events = events
            # in case multiple event that nodeOperatorId is the same we rely on order of the event.
            # Find the first event that matches the condition
            event = next((e for e in events if e.nodeOperatorId == no.id), None)

            # If a matching event is found, remove only the first occurrence
            if event:
                found = False
                remaining_events = []
                for e in events:
                    if e.nodeOperatorId == no.id and not found:
                        found = True  # Skip the first matching event
                    else:
                        remaining_events.append(e)
                events = remaining_events

            keys_after = min(no.total_keys_count, max(keys, no.deposited_keys_count))
            assert no.vetted_keys_count >= keys_after
            if no.vetted_keys_count == keys_after:
                # assert event is None
                if event is not None:
                    events = prev_events
                event_smaller += 1

            elif no.vetted_keys_count > keys_after:
                assert event is not None
                assert event.nodeOperatorId == no.id
                assert event.approvedValidatorsCount == keys_after
                no.vetted_keys_count = keys_after

                if staking_module_id in self.nor_ids:
                    self.update_summary_max_validators_count(no, staking_module_id)

        num_no = len(sel_no)
        assert num_no == num_event + event_smaller

        self.staking_modules[staking_module_id].nonce += 1
        logger.info(
            f"Decreased staking module vetted keys count for staking module {staking_module_id}"
        )

    #
    # Function:     setStakingModuleStatus
    # Caller:       sr_module_manager
    # Description:  Sets status for ONE staking module
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.staking_modules) > 0)
    def flow_set_staking_module_status(self) -> None:
        staking_module_id = self.get_staking_module_id()
        current_status = self.sr.getStakingModuleStatus(staking_module_id)
        status = random_int(0, 2)

        if current_status == status:
            with must_revert(self.sr.StakingModuleStatusTheSame):
                self.sr.setStakingModuleStatus(
                    _stakingModuleId=staking_module_id,
                    _status=status,
                    from_=self.sr_module_manager,
                )
            logger.info(f"Staking module status is the same.")
        else:
            self.sr.setStakingModuleStatus(
                _stakingModuleId=staking_module_id,
                _status=status,
                from_=self.sr_module_manager,
            )
            logger.info(
                f"Set staking module status {status} for staking module {staking_module_id}"
            )

    #
    # Function:     setWithdrawalCredentials
    # Caller:       admin (withdrawal credentials manager)
    # Description:  Sets new withdrawal credentials, the `onWithdrawalCredentialsChanged()` function is called on ALL staking modules
    #               Very rare flow
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.staking_modules) > 0, weight=100)
    def flow_set_withdrawal_credentials(self) -> None:
        withdrawal_credentials = random_bytes(32)
        tx = self.sr.setWithdrawalCredentials(withdrawal_credentials, from_=self.admin)
        for sm in self.staking_modules.values():
            if sm.is_csm:
                self.make_zero_removal_charge(sm.id)
            else:
                if len(sm.node_operators) == 0:
                    continue

                trimmed_keys_count = self.invalidate_ready_to_deposit_keys_range(
                    0,
                    len(sm.node_operators) - 1,
                    list(sm.node_operators.values()),
                    sm.id,
                )
                if trimmed_keys_count > 0:
                    sm.nonce += 1

        logger.info(f"Set new withdrawal credentials")

    """
        Deposit Security Module flows
    """

    #
    # Function:     setPauseIntentValidityPeriodBlocks
    # Caller:       admin
    # Description:  Sets pause intent validity period blocks
    # Status:       Done
    #
    @flow()
    def flow_set_pause_intent_validity_period_blocks(self) -> None:
        new_value = random_int(1, 100)
        self.dsm.setPauseIntentValidityPeriodBlocks(new_value, from_=self.admin)
        logger.info(f"Set new pause intent validity period blocks")

    #
    # Function:     setMaxOperatorsPerUnvetting
    # Caller:       admin
    # Description:  Sets max operators per unvetting
    # Status:       Done
    #
    @flow()
    def flow_set_max_operators_per_unvetting(self) -> None:
        new_value = random_int(1, 100)
        self.dsm.setMaxOperatorsPerUnvetting(new_value, from_=self.admin)
        logger.info(f"Set new max operators per unvetting")

    #
    # Function:     setGuardianQuorum
    # Caller:       admin
    # Description:  Sets guardian quorum, can be any value.
    # Status:       Done
    #
    @flow()
    def flow_set_guardian_quorum(self) -> None:
        new_value = random_int(0, len(self.dsm_guardians))
        self.dsm.setGuardianQuorum(new_value, from_=self.admin)
        self.dsm_quorum = new_value
        logger.info(f"Set new guardian quorum")

    #
    # Function:     addGuardian
    # Caller:       admin
    # Description:  Adds ONE guardian
    # Status:       Done
    #
    @flow(max_times=6)
    def flow_add_guardian(self) -> None:
        guardian = random_account()
        new_quorum = random_int(0, len(self.dsm_guardians) + 1)
        if guardian in self.dsm_guardians:
            with must_revert(self.dsm.DuplicateAddress):
                self.dsm.addGuardian(guardian, new_quorum, from_=self.admin)
            logger.info(f"Guardian already exists")
        else:
            self.dsm.addGuardian(guardian, new_quorum, from_=self.admin)
            self.dsm_quorum = new_quorum
            self.dsm_guardians.append(guardian)
            logger.info(f"Added guardian")

    #
    # Function:     addGuardians
    # Caller:       admin
    # Description:  Adds MANY guardians and sets quorum
    # Status:       Done
    #
    @flow(max_times=3)
    def flow_add_guardians(self) -> None:
        num_guardians = random_int(1, 10)
        guardians = []
        for _ in range(num_guardians):
            guardian = random_account()
            if guardian in self.dsm_guardians:
                continue
            self.dsm_guardians.append(guardian)
            guardians.append(guardian)
        new_quorum = random_int(0, len(self.dsm_guardians))
        self.dsm_quorum = new_quorum
        self.dsm.addGuardians(guardians, new_quorum, from_=self.admin)
        logger.info(f"Added {len(guardians)} guardians")

    #
    # Function:     removeGuardian
    # Caller:       admin
    # Description:  Removes ONE guardian and sets quorum
    # Status:       Done
    #
    @flow(max_times=4)
    def flow_remove_guardian(self) -> None:
        if len(self.dsm_guardians) == 0:
            return

        guardian = random.choice(self.dsm_guardians)
        new_quorum = random_int(0, len(self.dsm_guardians) - 1)
        self.dsm_quorum = new_quorum
        self.dsm.removeGuardian(guardian, new_quorum, from_=self.admin)
        self.dsm_guardians.remove(guardian)
        logger.info(f"Removed guardian")

    #
    # Function:     pauseDeposits
    # Caller:       Any guardian (sigs)
    # Description:  Pauses deposits
    # Status:       Done
    #
    @flow(weight=10)
    def flow_pause_deposits(self) -> None:
        if len(self.dsm_guardians) == 0:
            return

        constraint = (
            chain.blocks["pending"].number
            - self.dsm.getPauseIntentValidityPeriodBlocks()
        )
        block_number = random_int(constraint, chain.blocks["pending"].number)

        guardian = random.choice(self.dsm_guardians)
        sig = guardian.sign_hash(
            keccak256(
                abi.encode(self.dsm.PAUSE_MESSAGE_PREFIX(), uint256(block_number))
            )
        )
        r, vs = sig_to_compact(sig[:32], sig[32:64], sig[64:65])
        pause_sig = self.dsm.Signature(r, vs)
        self.dsm.pauseDeposits(block_number, pause_sig, from_=random_address())
        self.dsm_paused = True
        logger.info(f"Paused deposits")

    #
    # Function:     unpauseDeposits
    # Caller:       admin
    # Description:  Unpauses deposits
    # Status:       Done
    #
    @flow(precondition=lambda self: self.dsm_paused == True)
    def flow_unpause_deposits(self) -> None:
        if not self.dsm_paused:
            with must_revert(self.dsm.DepositsNotPaused):
                self.dsm.unpauseDeposits(from_=self.admin)
        else:
            self.dsm.unpauseDeposits(from_=self.admin)
            self.dsm_paused = False
            logger.info(f"Unpaused deposits")

    #
    # Function:     depositBufferedEther
    # Caller:       Guardians above quorum (sigs)
    # Description:  Deposits ether. Council Daemon check added key to check validity of keys, and if it's invalid, it will soft pause and stop module or unvetting keys.
    # Status:       Done
    #
    @flow(weight=400)
    def flow_deposit_buffered_ether(self) -> None:
        if (
            len(self.dsm_guardians) == 0
            or self.dsm_quorum == 0
            or len(self.staking_modules) == 0
        ):
            return

        guardian = random.choice(self.dsm_guardians)
        deposit_block = random_int(
            chain.blocks["finalized"].number - 64, chain.blocks["finalized"].number
        )
        deposit_blockhash = bytes32(bytes.fromhex(chain.blocks[deposit_block].hash[2:]))
        id = random_int(1, len(self.staking_modules))

        # state for calculation
        withdrawalReserve = self.withdrawal_queue.unfinalizedStETH()
        buffered_eth = LIDO.getBufferedEther()
        depositable_eth = max(buffered_eth - withdrawalReserve, 0)
        depositable_count = depositable_eth // (32 * 10**18)

        logger.debug(f"bufferd eth: {buffered_eth}")
        logger.debug(f"depositable_eth: {depositable_eth}")

        quorum_counter = 0
        raw_signatures = []
        for guardian in self.dsm_guardians:
            if quorum_counter == self.dsm_quorum:
                break

            raw_signatures.append(
                (
                    guardian.address,
                    guardian.sign_hash(
                        keccak256(
                            abi.encode(
                                self.dsm.ATTEST_MESSAGE_PREFIX(),
                                uint256(deposit_block),
                                deposit_blockhash,
                                DEPOSIT_CONTRACT.get_deposit_root(),
                                uint256(id),
                                uint256(self.sr.getStakingModuleNonce(id)),
                            )
                        )
                    ),
                )
            )
            quorum_counter += 1

        sorted_raw_signatures = [
            sig[1] for sig in sorted(raw_signatures, key=lambda guardian: guardian[0])
        ]
        sorted_signatures = []
        for sig in sorted_raw_signatures:
            r, vs = sig_to_compact(sig[:32], sig[32:64], sig[64:65])
            sorted_signatures.append(self.dsm.Signature(r, vs))

        sum_csm_depositable_keys = 0
        # needed by CSM
        if self.staking_modules[id].is_csm:
            csm = self.csms[id]
            depositable_keys = {
                no.id: csm.module.getNodeOperator(no.id).depositableValidatorsCount
                for no in csm.node_operators.values()
            }

            for key in depositable_keys.values():
                sum_csm_depositable_keys += key

        with may_revert() as e:
            tx = self.dsm.depositBufferedEther(
                blockNumber=deposit_block,
                blockHash=deposit_blockhash,
                depositRoot=DEPOSIT_CONTRACT.get_deposit_root(),
                stakingModuleId=id,
                nonce=self.sr.getStakingModuleNonce(id),
                depositCalldata=bytes(),
                sortedGuardianSignatures=sorted_signatures,
                from_=random_address(),
            )

        if isinstance(e.value, DepositSecurityModule.DepositsArePaused):
            assert self.dsm_paused == True
            logger.debug(f"Deposits are paused")
            return
        elif isinstance(e.value, DepositSecurityModule.DepositTooFrequent):
            assert self.dsm.isMinDepositDistancePassed(id) == False
            logger.debug(f"Deposit Min Distance not passed")
            return
        elif isinstance(e.value, DepositSecurityModule.DepositInactiveModule):
            assert (
                self.sr.getStakingModuleStatus(id)
                != StakingRouter.StakingModuleStatus.Active
            )
            logger.debug(f" Staking module is not active")
            return

        if self.wq_is_bunker_mode == True:
            assert e.value == Error("CAN_NOT_DEPOSIT")
            logger.debug(f"Bunker Mode")
            return

        ## allocation count!!
        total_active_validators = 0
        for i in range(1, len(self.staking_modules) + 1):
            total_active_validators += (
                self.staking_modules[i].total_deposited_keys_count
                - self.staking_modules[i].total_exited_keys_count_in_sr
            )

        allocations = []
        targetValidators = depositable_count  # _depositsToAllocate arg in _getDepositsAllocation function
        capacities = []
        for i in range(1, len(self.staking_modules) + 1):
            # use sr of exited  since it always higher, max is used in source
            active_validators = (
                self.staking_modules[i].total_deposited_keys_count
                - self.staking_modules[i].total_exited_keys_count_in_sr
            )

            allocations.append(active_validators)

            if (
                self.sr.getStakingModuleStatus(i)
                == StakingRouter.StakingModuleStatus.Active
            ):
                available_validators = self.staking_modules[
                    i
                ].total_depostable_keys_count
            else:
                available_validators = 0

            capacity = min(
                active_validators + available_validators,
                (
                    self.staking_modules[i].stake_share_limit
                    * (total_active_validators + targetValidators)
                )
                // TOTAL_BASIS_POINTS,
            )
            capacities.append(capacity)

        self.min_allocation(allocations, capacities, targetValidators)

        possible_deposits_count = allocations[id - 1] - (
            self.staking_modules[id].total_deposited_keys_count
            - self.staking_modules[id].total_exited_keys_count_in_sr
        )
        allocation_count = min(
            possible_deposits_count, self.staking_modules[id].max_deposits_per_block
        )

        if isinstance(e.value, CSModule.NotEnoughKeys):
            return

        assert e.value is None
        target_events = [
            e
            for e in tx.events
            if isinstance(
                e, NodeOperatorsRegistryMigrated.DepositedSigningKeysCountChanged
            )
        ]

        if TEST_OLD_SOLIDITY:
            target_events = []
            for event in tx.raw_events:
                if (
                    event.topics[0]
                    == NodeOperatorsRegistryMigrated.DepositedSigningKeysCountChanged.selector
                ):
                    no_id = abi.decode(event.topics[1], [uint256])
                    deposited_validators_count = abi.decode(event.data, [uint256])
                    target_events.append(
                        NodeOperatorsRegistryMigrated.DepositedSigningKeysCountChanged(
                            no_id, deposited_validators_count
                        )
                    )

        if self.staking_modules[id].is_csm:
            self.on_obtain_deposit_data(id, depositable_keys, tx)

        # calculation for StakingModule.obtainDepositData()
        # this allocation_count number will be the argument of StakingModule.obtainDepositData()

        if id in self.nor_ids:  # if nor
            active_key_ids = []
            active_key_allocation = []
            active_key_capacity = []
            for no_id in range(len(self.staking_modules[id].node_operators)):
                no = self.staking_modules[id].node_operators[no_id]
                active_key_ids.append(no_id)
                active_key_allocation.append(
                    no.deposited_keys_count - no.exited_keys_count
                )
                active_key_capacity.append(no.max_keys_count - no.exited_keys_count)

            allocated_active_keys = copy.deepcopy(active_key_allocation)
            allocated_key_count = self.min_allocation(
                allocated_active_keys, active_key_capacity, allocation_count
            )
            assert allocated_key_count == allocation_count

            index = 0
            for i in range(len(active_key_ids)):
                if active_key_allocation[i] == allocated_active_keys[i]:
                    continue

                new_deposited_keys = (
                    allocated_active_keys[i]
                    + self.staking_modules[id]
                    .node_operators[active_key_ids[i]]
                    .exited_keys_count
                )

                assert target_events[index].nodeOperatorId == active_key_ids[i]
                assert (
                    target_events[index].depositedValidatorsCount == new_deposited_keys
                )
                no = self.staking_modules[id].node_operators[active_key_ids[i]]
                for j in range(no.deposited_keys_count, new_deposited_keys):
                    assert no.keys[j].key_state == KeyState.Vetted
                    no.keys[j].key_state = KeyState.Deposited
                no.deposited_keys_count = new_deposited_keys
                index += 1

            # if no validator deposited, nonce should not be increased
            if index != 0:
                self.staking_modules[id].nonce += 1

                # min allocation calculate how many could deposit to this module.
                # but depositBufferedEther specicfy staking module id!!!
                if id in self.nor_ids:  # if nor
                    self.staking_modules[
                        id
                    ].total_deposited_keys_count += allocation_count
                    self.staking_modules[
                        id
                    ].total_depostable_keys_count -= allocation_count

                if (
                    self.beacon_chain.current_frame_index
                    not in self.deposited_inc_in_frame
                ):
                    self.deposited_inc_in_frame[
                        self.beacon_chain.current_frame_index
                    ] = 0
                self.deposited_inc_in_frame[
                    self.beacon_chain.current_frame_index
                ] += allocation_count
                self.lido_beacon_state.deposited_validators += allocation_count

                self.balances[LIDO] -= allocation_count * 32 * 10**18
                logger.info(
                    f"Deposited ether for NOR {id} total {allocated_key_count} keys"
                )

    #
    # Function:     unvetSigningKeys
    # Caller:       Any guardian (sigs)
    # Description:  Unvetting signing keys for MANY node operators and ONE staking module.
    #               Calls `decreaseStakingModuleVettedKeysCountByNodeOperator` on SR.
    # Status:       Done
    #
    @flow(weight=50, precondition=lambda self: len(self.staking_modules) > 0)
    def flow_unvet_signing_keys(self) -> None:
        if (
            len(self.dsm_guardians) == 0
            or self.dsm_quorum == 0
            or len(self.staking_modules) == 0
        ):
            return

        guardian = random.choice(self.dsm_guardians)
        deposit_block = random_int(
            chain.blocks["finalized"].number - 64, chain.blocks["finalized"].number
        )
        deposit_blockhash = bytes32(bytes.fromhex(chain.blocks[deposit_block].hash[2:]))
        staking_module_id = random.choice(list(self.staking_modules.values())).id
        if staking_module_id in self.nor_ids:
            nos = self.staking_modules[staking_module_id].node_operators
            if len(nos) == 0:
                logger.info(f"Empty NOS")
                return
            nonce = self.staking_modules[staking_module_id].nonce

        else:
            nos = self.csms[staking_module_id].node_operators
            if len(nos) == 0:
                logger.info(f"Empty NOS")
                return
            nonce = self.csms[staking_module_id].nonce

        (no_ids_encoded, keys_encoded, sel_no, key_counts) = (
            self.random_node_operators_and_keys_count("vetted", nos)
        )

        if staking_module_id not in self.nor_ids:
            depositable_before = {}
            for no in sel_no:
                depositable_before[no.id] = (
                    self.csms[staking_module_id]
                    .module.getNodeOperator(no.id)
                    .depositableValidatorsCount
                )

        raw_sig = guardian.sign_hash(
            keccak256(
                abi.encode(
                    self.dsm.UNVET_MESSAGE_PREFIX(),
                    uint256(deposit_block),
                    deposit_blockhash,
                    uint256(staking_module_id),
                    uint256(nonce),
                    no_ids_encoded,
                    keys_encoded,
                )
            )
        )
        r, vs = sig_to_compact(raw_sig[:32], raw_sig[32:64], raw_sig[64:65])
        unvet_sig = self.dsm.Signature(r, vs)

        events = []
        with may_revert() as e:
            tx = self.dsm.unvetSigningKeys(
                blockNumber=deposit_block,
                blockHash=deposit_blockhash,
                stakingModuleId=staking_module_id,
                nonce=nonce,
                nodeOperatorIds=no_ids_encoded,
                vettedSigningKeysCounts=keys_encoded,
                sig=unvet_sig,
                from_=guardian,
            )
            if staking_module_id in self.nor_ids:
                events = [
                    e
                    for e in tx.events
                    if isinstance(
                        e, NodeOperatorsRegistryMigrated.VettedSigningKeysCountChanged
                    )
                ]
                if TEST_OLD_SOLIDITY:
                    events = []
                    for event in tx.raw_events:
                        if (
                            event.topics[0]
                            == NodeOperatorsRegistryMigrated.VettedSigningKeysCountChanged.selector
                        ):
                            no_id = abi.decode(event.topics[1], [uint256])
                            vetted_validators_count = abi.decode(event.data, [uint256])
                            events.append(
                                NodeOperatorsRegistryMigrated.VettedSigningKeysCountChanged(
                                    no_id, vetted_validators_count
                                )
                            )
            else:
                events = [
                    e
                    for e in tx.events
                    if isinstance(e, CSModule.VettedSigningKeysCountChanged)
                ]
        # simulation wether revert or not
        is_revert = False
        temp_vetted_keys_counts = {}

        if self.dsm.getMaxOperatorsPerUnvetting() < len(key_counts):
            is_revert = True

        if is_revert:
            assert e.value == DepositSecurityModule.UnvetPayloadInvalid()
            return

        for i in range(len(sel_no)):
            no = sel_no[i]
            if no.id not in temp_vetted_keys_counts:
                temp_vetted_keys_counts[no.id] = no.vetted_keys_count
            keys = key_counts[i]
            keys_after = min(no.total_keys_count, max(keys, no.deposited_keys_count))
            if temp_vetted_keys_counts[no.id] < keys_after:
                is_revert = True
                break
            else:
                temp_vetted_keys_counts[no.id] = keys_after

        if is_revert:
            if staking_module_id in self.nor_ids:
                assert (
                    e.value == Error("VETTED_KEYS_COUNT_INCREASED")
                    or e.value == DepositSecurityModule.UnvetPayloadInvalid()
                )
            else:
                assert e.value == CSModule.InvalidVetKeysPointer()
            return

        debug_counter = 0

        if staking_module_id not in self.nor_ids:
            temp_vetted_keys_counts = {}
            for i in range(len(sel_no)):
                no = sel_no[i]
                if no.id not in temp_vetted_keys_counts:
                    temp_vetted_keys_counts[no.id] = no.vetted_keys_count
                if key_counts[i] < no.deposited_keys_count:
                    assert e.value == CSModule.InvalidVetKeysPointer()
                    return
                if key_counts[i] >= temp_vetted_keys_counts[no.id]:
                    assert e.value == CSModule.InvalidVetKeysPointer()
                    return
                temp_vetted_keys_counts[no.id] = key_counts[i]

        assert e.value is None

        event_smaller = 0
        num_events = len(events)
        for i in range(len(sel_no)):
            no = sel_no[i]
            keys = key_counts[i]
            keys_after = min(no.total_keys_count, max(keys, no.deposited_keys_count))
            event = next((e for e in events if e.nodeOperatorId == no.id), None)
            prev_events = events
            if event:
                found = False
                remaining_events = []
                for e in events:
                    if e.nodeOperatorId == no.id and not found:
                        found = True  # Skip the first matching event
                    else:
                        remaining_events.append(e)
                events = remaining_events

            if no.vetted_keys_count == keys_after:
                if event is not None:
                    events = prev_events
                event_smaller += 1
                # "Vetted keys same"

            else:
                assert no.vetted_keys_count > keys_after
                prev_vetted = no.vetted_keys_count
                assert event is not None
                assert event.nodeOperatorId == no.id
                if isinstance(
                    event, NodeOperatorsRegistryMigrated.VettedSigningKeysCountChanged
                ):
                    assert event.approvedValidatorsCount == keys_after
                    assert False
                else:
                    assert isinstance(event, CSModule.VettedSigningKeysCountChanged)
                    assert event.vettedKeysCount == keys_after
                    assert no.id in depositable_before
                    self._reenqueue(
                        self.csms[staking_module_id], no.id, depositable_before[no.id]
                    )

                    assert (
                        CSModule.VettedSigningKeysCountChanged(no.id, keys_after)
                        in tx.events
                    )
                    assert CSModule.VettedSigningKeysCountDecreased(no.id) in tx.events
                    assert (
                        CSModule.NonceChanged(self.csms[staking_module_id].nonce + 1)
                        in tx.events
                    )

                no.vetted_keys_count = keys_after

                debug_counter += prev_vetted - keys_after

                for i in range(keys_after, prev_vetted):
                    assert no.keys[i].key_state == KeyState.Vetted
                    no.keys[i].key_state = KeyState.Added

                if staking_module_id in self.nor_ids:
                    self.update_summary_max_validators_count(no, staking_module_id)

        assert num_events + event_smaller == len(sel_no)

        if staking_module_id in self.nor_ids:
            self.staking_modules[staking_module_id].nonce += 1
        else:
            self.csms[staking_module_id].nonce += 1
            csm = self.csms[staking_module_id]

        logger.info(
            f"Unvetted signing keys for staking module {staking_module_id} with unvet {debug_counter} keys"
        )

    """
        Node Operator Registry flows
    """

    #
    # Function:     addNodeOperator
    # Caller:       no_manager
    # Description:  nor specific operation Adds a new node operator
    # Status:       Done
    #
    @flow(
        max_times=NOR_MAX_COUNT * NOR_NO_AVG_COUNT,
        precondition=lambda self: len(self.nor_ids) > 0,
    )
    def flow_add_node_operator(self) -> None:
        id = random.choice(self.nor_ids)
        name = random_string(10, 10)
        rewards_account = random_address()
        active_operators_count = self.nors[id].getActiveNodeOperatorsCount()

        tx = self.nors[id].addNodeOperator(name, rewards_account, from_=self.no_manager)
        assert self.nors[id].getActiveNodeOperatorsCount() == active_operators_count + 1

        no_id = 0

        if TEST_OLD_SOLIDITY:
            e = None
            for event in tx.raw_events:
                if (
                    event.topics[0]
                    == NodeOperatorsRegistryMigrated.NodeOperatorAdded.selector
                ):
                    e = event
            raw_data = e.data
            padding_length = 32 - (len(raw_data) % 32)
            padded_data = raw_data + b"\x00" * padding_length
            (ret_no_id, ret_name, ret_reward_address, ret_limit) = abi.decode(
                padded_data, [uint256, str, Address, uint64]
            )
            assert ret_name == name
            assert ret_no_id not in self.staking_modules[id].node_operators
            assert ret_reward_address == rewards_account
            no_id = ret_no_id
        else:
            e = next(
                (
                    e
                    for e in tx.events
                    if isinstance(e, NodeOperatorsRegistryMigrated.NodeOperatorAdded)
                ),
                None,
            )
            assert e is not None, "Expected event does not exist"
            assert e.name == name
            assert e.rewardAddress == rewards_account
            assert e.nodeOperatorId not in self.staking_modules[id].node_operators
            no_id = e.nodeOperatorId

        self.staking_modules[id].node_operators[no_id] = NodeOperator(
            id=no_id,
            name=name,
            rewards_account=rewards_account,
            active=True,
            exited_keys_count=0,
            deposited_keys_count=0,
            vetted_keys_count=0,
            total_keys_count=0,
            stuck_keys_count=0,
            refunded_keys_count=0,
            target_limit_mode=0,
            target_limit=0,
            max_keys_count=0,
            summary_max_keys_count=0,
            stuck_penalty_end_timestamp=0,
            keys=[],
            exit_requested_key_count=0,
            rewards_account_share=LIDO.sharesOf(rewards_account),
        )

        self.staking_modules[id].active_node_operators += 1

        logger.info(f"Added node operator {no_id}")

    #
    # Function:     activateNodeOperator
    # Caller:       no_manager
    # Description:  Activates ONE node operator
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.nor_ids) > 0)
    def flow_activate_node_operator(self) -> None:
        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))
        with may_revert() as e:
            tx = self.nors[id].activateNodeOperator(no.id, from_=self.no_manager)

        if e.value == Error("WRONG_OPERATOR_ACTIVE_STATE"):
            assert no.active == True
        else:
            assert e.value is None
            assert no.active == False
            event = next(
                (
                    e
                    for e in tx.events
                    if isinstance(
                        e, NodeOperatorsRegistryMigrated.NodeOperatorActiveSet
                    )
                )
            )
            assert event is not None
            no.active = True
            self.staking_modules[id].nonce += 1

            self.staking_modules[id].active_node_operators += 1
            logger.info(f"Activated node operator {no.id}")

    #
    # Function:     deactivateNodeOperator
    # Caller:       no_manager
    # Description:  Deactivates ONE node operator, nor specific
    # Status:       Done
    #
    @flow(weight=50, precondition=lambda self: len(self.nor_ids) > 0)
    def flow_deactivate_node_operator(self) -> None:
        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))
        with may_revert() as e:
            tx = self.nors[id].deactivateNodeOperator(no.id, from_=self.no_manager)

        if e.value == Error("WRONG_OPERATOR_ACTIVE_STATE"):
            assert no.active == False
        else:
            assert e.value is None
            assert no.active == True
            event = next(
                (
                    e
                    for e in tx.events
                    if isinstance(
                        e, NodeOperatorsRegistryMigrated.NodeOperatorActiveSet
                    )
                )
            )
            assert event is not None
            no.active = False
            self.staking_modules[id].nonce += 1
            self.staking_modules[id].active_node_operators -= 1

            if no.vetted_keys_count > no.deposited_keys_count:

                prev_vetted = no.vetted_keys_count
                no.vetted_keys_count = no.deposited_keys_count

                for i in range(no.vetted_keys_count, prev_vetted):
                    assert no.keys[i].key_state == KeyState.Vetted
                    no.keys[i].key_state = KeyState.Added

                event = next(
                    (
                        e
                        for e in tx.events
                        if isinstance(
                            e,
                            NodeOperatorsRegistryMigrated.VettedSigningKeysCountChanged,
                        )
                    ),
                    None,
                )
                self.update_summary_max_validators_count(no, id)

            logger.info(f"Deactivated node operator {no.id}")

    #
    # Function:     setNodeOperatorName
    # Caller:       no_manager
    # Description:  Sets name for ONE node operator, nor specific
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.nor_ids) > 0)
    def flow_set_node_operator_name(self) -> None:

        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))
        name = random_string(10, 10)

        self.nors[id].setNodeOperatorName(no.id, name, from_=self.no_manager)
        no.name = name

        logger.info(f"Set node operator name for sm {id}, node operator {no.id}")

    #
    # Function:     setNodeOperatorRewardAddress
    # Caller:       no_manager
    # Description:  Sets reward address for ONE node operator
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.nor_ids) > 0)
    def flow_set_node_operator_reward_address(self) -> None:
        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))
        reward_address = random_address()

        self.nors[id].setNodeOperatorRewardAddress(
            no.id, reward_address, from_=self.no_manager
        )
        no.rewards_account = reward_address
        no.rewards_account_share = LIDO.sharesOf(reward_address)

        logger.info(
            f"Set node operator reward address {reward_address} for node operator {no.id}"
        )

    #
    # Function:     setNodeOperatorStakingLimit
    # Caller:       no_limiter
    # Description:  Sets staking limit for ONE node operator. Calls `_updateVettedSingingKeysCount()`, nor specific
    #               increase vetted key count for deposit , it can decrease, but it is not necessary? is not it ? the purpose of this is allow to deposit and it means added key to deposit key.
    # Status:       DONE
    #
    @flow(weight=400, precondition=lambda self: len(self.nor_ids) > 0)
    def flow_set_node_operator_staking_limit(self) -> None:

        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))

        if no.total_keys_count == 0:
            return

        new_vetted_keys_count = random_int(0, no.total_keys_count, max_prob=0.8)

        with may_revert() as e:
            tx = self.nors[id].setNodeOperatorStakingLimit(
                no.id, new_vetted_keys_count, from_=self.no_limiter
            )

        if e.value == Error("WRONG_OPERATOR_ACTIVE_STATE"):
            assert no.active == False
            return
        else:
            assert e.value is None
            event = next(
                (
                    e
                    for e in tx.events
                    if isinstance(
                        e, NodeOperatorsRegistryMigrated.VettedSigningKeysCountChanged
                    )
                ),
                None,
            )
            keys_after = min(
                no.total_keys_count, max(new_vetted_keys_count, no.deposited_keys_count)
            )

            if keys_after == no.vetted_keys_count:
                assert event is None
            else:
                prev_vetted = no.vetted_keys_count
                no.vetted_keys_count = keys_after
                self.update_summary_max_validators_count(no, id)
                if prev_vetted < no.vetted_keys_count:  # increase
                    for i in range(prev_vetted, no.vetted_keys_count):
                        assert no.keys[i].key_state == KeyState.Added
                        no.keys[i].key_state = KeyState.Vetted
                else:  # decrease
                    for i in range(no.vetted_keys_count, prev_vetted):
                        assert no.keys[i].key_state == KeyState.Vetted
                        no.keys[i].key_state = KeyState.Added

            self.staking_modules[id].nonce += 1
            logger.info(
                f"Set node operator staking limit {keys_after} for node operator {no.id}"
            )

    #
    # Function:     invalidateReadyToDepositKeysRange
    # Caller:       no_manager
    # Description:  Invalidates all unused validators keys for node operators in the given range, nor specific.
    #               unflow since setWithdrawalCredentials does this function call.
    # Status:       Done
    #
    # @flow(weight=1, precondition=lambda self: len(self.staking_modules) > 0)
    def flow_invalidate_ready_to_deposit_keys_range(self) -> None:
        id = random.choice(self.nor_ids)
        nos = list(self.staking_modules[id].node_operators.values())
        if len(nos) == 0:
            return
        index_from = random_int(0, len(nos) - 1)
        index_to = random_int(index_from, len(nos) - 1)

        tx = self.nors[id].invalidateReadyToDepositKeysRange(
            index_from, index_to, from_=self.no_manager
        )
        trimmed_keys_count = self.invalidate_ready_to_deposit_keys_range(
            index_from, index_to, nos, id
        )
        if trimmed_keys_count > 0:
            self.staking_modules[id].nonce += 1
        logger.info(f"Invalidated ready to deposit keys range!")

    #
    # Function:     addSigningKeys
    # Caller:       `_requireAuth((isRewardAddress && isActive) || canPerform(_sender, MANAGE_SIGNING_KEYS, arr(_nodeOperatorId)))`
    # Description:  Adds new signing keys for ONE node operator
    # Status:       Done
    #
    @flow(weight=400, precondition=lambda self: len(self.nor_ids) > 0)
    def flow_add_signing_keys(self) -> None:

        self.invariant_check_python_state()
        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))
        key_count = uint256(random_int(1, 10))

        PUBKEY_LENGTH = 48
        SIGNATURE_LENGTH = 96

        pkeys = b""
        sigs = b""

        prev_key_count = self.staking_modules[id].node_operators[no.id].total_keys_count

        adding_keys = []
        for i in range(key_count):
            pkey = bytes(random_bytes(PUBKEY_LENGTH))
            sig = bytes(random_bytes(SIGNATURE_LENGTH))

            while pkey == bytes(48):  # pkey must not zero bytes array
                pkey = bytes(random_bytes(PUBKEY_LENGTH))

            adding_keys.append(
                KeyInfo(pkey=pkey, signature=sig, key_state=KeyState.Added)
            )
            pkeys += pkey
            sigs += sig

        assert self.staking_modules[id].is_csm == False
        with may_revert() as e:
            tx = self.nors[id].addSigningKeys(
                no.id, key_count, pkeys, sigs, from_=no.rewards_account
            )
            event = next(
                (
                    e
                    for e in tx.events
                    if isinstance(
                        e, NodeOperatorsRegistryMigrated.TotalSigningKeysCountChanged
                    )
                ),
                None,
            )

        if e.value == Error("APP_AUTH_FAILED"):
            assert no.active == False
            return

        assert e.value is None

        target_event = None
        for event in tx.raw_events:
            if (
                event.topics[0]
                == NodeOperatorsRegistryMigrated.TotalSigningKeysCountChanged.selector
            ):
                nor_id = abi.decode(event.topics[1], [uint256])  # node operator id
                total_validators_count = abi.decode(event.data, [uint256])
                target_event = (
                    NodeOperatorsRegistryMigrated.TotalSigningKeysCountChanged(
                        nor_id, total_validators_count
                    )
                )

        assert target_event is not None
        assert target_event.nodeOperatorId == no.id
        assert target_event.totalValidatorsCount == no.total_keys_count + key_count
        no.total_keys_count = no.total_keys_count + key_count
        self.staking_modules[id].nonce += 1

        ret_pubkeys, ret_signatures, useds = self.nors[id].getSigningKeys(
            no.id, prev_key_count, key_count
        )

        self.staking_modules[id].node_operators[no.id].keys += adding_keys

        assert pkeys == ret_pubkeys
        assert sigs == ret_signatures
        for i in range(prev_key_count, no.total_keys_count):
            (pubkey, signature, used) = self.nors[id].getSigningKey(no.id, i)
            assert pubkey == no.keys[i].pkey
            assert signature == no.keys[i].signature

        logger.info(f"Added signing keys for node operator {no.id}")

    #
    # Function:     removeSigningKeys
    # Caller:       `_requireAuth((isRewardAddress && isActive) || canPerform(_sender, MANAGE_SIGNING_KEYS, arr(_nodeOperatorId)))`
    # Description:  Removes signing keys for ONE node operator
    # Status:       Done
    #
    @flow(weight=50, precondition=lambda self: len(self.nor_ids) > 0)
    def flow_remove_signing_keys(self) -> None:
        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))

        if no.total_keys_count == 0:
            return

        if no.deposited_keys_count == no.total_keys_count:
            return

        from_index = random_int(no.deposited_keys_count, no.total_keys_count - 1)
        keys_count = random_int(0, no.total_keys_count - from_index)

        with may_revert() as e:
            tx = self.nors[id].removeSigningKeys(
                no.id, from_index, keys_count, from_=no.rewards_account
            )

        if e.value == Error("APP_AUTH_FAILED"):
            assert no.active == False
            return
        else:
            assert e.value is None

            event = next(
                (
                    e
                    for e in tx.events
                    if isinstance(
                        e, NodeOperatorsRegistryMigrated.TotalSigningKeysCountChanged
                    )
                ),
                None,
            )
            if keys_count != 0:

                no.total_keys_count = no.total_keys_count - keys_count
                if from_index < no.vetted_keys_count:
                    prev_vetted = no.vetted_keys_count
                    no.vetted_keys_count = from_index

                    for i in range(from_index, prev_vetted):
                        assert (
                            no.keys[i].key_state == KeyState.Vetted
                            or no.keys[i].key_state == KeyState.Added
                        )
                        no.keys[i].key_state = KeyState.Added

                self.update_summary_max_validators_count(no, id)
                self.staking_modules[id].nonce += 1

            # update keys state
            keys = self.staking_modules[id].node_operators[no.id].keys
            # and remove key that end of keys list.

            for i in range(from_index + keys_count, from_index, -1):
                cur_offset = i - 1
                if i < len(keys):
                    # Move the last key to the current position
                    keys[cur_offset] = keys[-1]
                # Remove the last key
                keys.pop()

            for i in range(no.total_keys_count):
                (pkey, sign, _) = self.nors[id].getSigningKey(no.id, i)
                assert pkey == keys[i].pkey
                assert sign == keys[i].signature

            self.staking_modules[id].node_operators[no.id].keys = keys

            logger.info(f"Removed signing keys for node operator {no.id}")

    #
    # Function:     clearNodeOperatorPenalty
    # Caller:       Anyone
    # Description:  Clears penalty for ONE node operator
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.nor_ids) > 0)
    def flow_clear_node_operator_penalty(self) -> None:
        id = random.choice(self.nor_ids)
        nos = self.staking_modules[id].node_operators
        if len(nos) == 0:
            return
        no = random.choice(list(nos.values()))

        with may_revert() as e:
            tx = self.nors[id].clearNodeOperatorPenalty(no.id, from_=random_address())

        is_penalized = (
            no.refunded_keys_count < no.stuck_keys_count
            or chain.blocks["latest"].timestamp <= no.stuck_penalty_end_timestamp
        )
        if (not is_penalized) and (no.stuck_penalty_end_timestamp != 0):
            assert e.value is None
            no.stuck_penalty_end_timestamp = 0
            self.update_summary_max_validators_count(no, id)
            self.staking_modules[id].nonce += 1
            logger.info(f"Cleared node operator penalty for node operator {no.id}")
        else:
            assert e.value == Error("CANT_CLEAR_PENALTY")
            return

    #
    # Function:     setStuckPenaltyDelay
    # Caller:       no_manager
    # Description:  Sets stuck penalty delay, not IStakingModule
    # Status:       Done
    #
    @flow(precondition=lambda self: len(self.nor_ids) > 0)
    def flow_set_stuck_penalty_delay(self) -> None:
        delay = random_int(1 * 60 * 60, 10 * 24 * 60 * 60)
        id = random.choice(self.nor_ids)
        tx = self.nors[id].setStuckPenaltyDelay(delay, from_=self.no_manager)
        self.staking_modules[id].stuck_penalty_delay = delay
        logger.info(f"Set stuck penalty delay to: {delay}")

    #
    # Function:     distributeReward
    # Caller:       Anyone
    # Description:  Distributes rewards for ONE staking module, it requred to be the reward distribution state is ReadyForDistribution
    # Status:       Done
    #

    @flow(precondition=lambda self: len(self.nor_ids) > 0)
    def flow_distribute_reward(self) -> None:

        id = random.choice(self.nor_ids)
        if (
            self.staking_modules[id].reward_distribution_state
            != NodeOperatorsRegistryMigrated.RewardDistributionState.ReadyForDistribution
        ):
            return

        for no in self.staking_modules[id].node_operators.values():
            assert self.shares[no.rewards_account] == LIDO.sharesOf(no.rewards_account)

        prev_module_share = LIDO.sharesOf(self.deployed_staking_modules[id])
        assert prev_module_share == self.shares[self.nors[id]]

        tx = self.nors[id].distributeReward(from_=random_account())
        self.staking_modules[id].reward_distribution_state = (
            NodeOperatorsRegistryMigrated.RewardDistributionState.Distributed
        )

        total_active_validators = 0

        for no in self.staking_modules[id].node_operators.values():
            if no.active == False:
                continue
            total_active_validators += no.deposited_keys_count - no.exited_keys_count

        if total_active_validators == 0:
            return

        to_burn = 0

        for no in self.staking_modules[id].node_operators.values():
            share = 0
            if no.active == True:

                active_key_count = no.deposited_keys_count - no.exited_keys_count
                share = (
                    active_key_count * prev_module_share
                ) // total_active_validators
                if share < 2:
                    continue
                if (
                    no.stuck_penalty_end_timestamp >= chain.blocks["latest"].timestamp
                    or no.stuck_keys_count > no.refunded_keys_count
                ):
                    assert self.nors[id].isOperatorPenalized(no.id) == True
                    share //= 2

                    to_burn += share
                    self.shares[self.nors[id]] -= share

                logger.debug(
                    f"sm: {id}, no: {no.id}, reward transfered {share} of share"
                )
                no.rewards_account_share += share
                self.shares[no.rewards_account] += share
                self.shares[self.nors[id]] -= share

        self.shares[BURNER] += to_burn
        logger.info(
            f"Distributed rewards of {id} staking module to node operators stETH share {prev_module_share - LIDO.sharesOf(self.deployed_staking_modules[id])}"
        )

    """
        Lido flows
    """

    #
    # Function:     submit
    # Caller:       Anyone
    # Description:  Submits ETH to Lido for stETH
    # Status:       Done
    #
    @flow(weight=1000)
    def flow_add_eth(self) -> None:

        alice = random_account()

        currentStakeLimit = LIDO.getStakeLimitFullInfo()[2]

        # Want to have a lot of buffered ether for deposit key
        value = 0
        if random.random() < 0.1:
            value = random_int(5 * 10**17, currentStakeLimit + 100, min_prob=0.5)
        else:
            value = random_int(0, 10**19)
        alice.balance = max(alice.balance, value)
        with may_revert() as e:
            tx = LIDO.submit(Address(0), value=value, from_=alice)

        if e.value == Error("STAKE_LIMIT"):
            logger.info(f"Alice submitted too much ether.")
            return
        else:
            assert e.value is None
            self.balances[LIDO] += value
            self.balances[alice] = alice.balance
            self.shares[alice] += tx.return_value

            event = next(
                (e for e in tx.events if isinstance(e, ExternalEvent) and e._event_full_name == "Lido.TransferShares"),
                None,
            )
            assert event is not None
            assert hasattr(event, "to")
            assert getattr(event, "to") == alice.address
            logger.info(f"Alice submitted {value / (10**18)} ether.")

            for csm in self.csms.values():
                t = tx.block.timestamp
                for no in csm.node_operators.values():
                    unbonded = (
                        no.total_keys_count
                        - no.withdrawn_keys
                        - self._get_keys_by_eth(no, t, False)
                    )
                    assert csm.accounting.getUnbondedKeysCountToEject(no.id) == max(
                        unbonded, 0
                    )
                    assert csm.accounting.getUnbondedKeysCount(no.id) == max(
                        no.total_keys_count
                        - no.withdrawn_keys
                        - self._get_keys_by_eth(no, t, True),
                        0,
                    )

    #
    # Function:     requestWithdrawals
    # Caller:       Anyone
    # Description:  send request to withdraw ETH by sending stETH
    # Status:       DONE
    #
    @flow(weight=100)
    def flow_withdraw_request(self):

        valid_accounts = [ac for ac in chain.accounts if self.shares[ac] > 0]
        if valid_accounts:
            alice = random.choice(valid_accounts)
        else:
            return

        prev_balance = self.shares[alice]

        if self.withdrawal_queue.MIN_STETH_WITHDRAWAL_AMOUNT() > prev_balance:
            return

        withdraw_amount = random_int(
            self.withdrawal_queue.MIN_STETH_WITHDRAWAL_AMOUNT(), prev_balance
        )
        withdraw_amount = min(
            self.withdrawal_queue.MAX_STETH_WITHDRAWAL_AMOUNT(), withdraw_amount
        )
        LIDO.approve(self.withdrawal_queue, withdraw_amount, from_=alice)

        tx = self.withdrawal_queue.requestWithdrawals(
            [withdraw_amount], alice, from_=alice
        )

        event = next(
            (e for e in tx.events if isinstance(e, ExternalEvent) and e._event_full_name == "Lido.TransferShares"), None
        )
        assert event is not None
        assert hasattr(event, "sharesValue")
        share_value =  getattr(event, "sharesValue")

        assert LIDO.sharesOf(alice) + event.sharesValue == self.shares[alice]

        self.shares[alice] -= event.sharesValue

        request_ids = tx.return_value
        for id in request_ids:
            self.withdraw_request_owner[id] = alice

        self.withdraw_request_ids[0] += request_ids
        logger.info(f"Alice requested withdrawal of {withdraw_amount} stETH of ETH")

    #
    # Function:     claimWithdrawal
    # Caller:       Anyone
    # Description:  claim requested withdrawal to get ETH
    # Status:       DONE
    #
    @flow(precondition=lambda self: len(self.finalized_withdraw_request_ids) > 0)
    def flow_claim_withdrawal(self):

        claim_id = random.choice(self.finalized_withdraw_request_ids)

        self.finalized_withdraw_request_ids.remove(claim_id)

        alice = self.withdraw_request_owner[claim_id]
        tx = self.withdrawal_queue.claimWithdrawal(claim_id, from_=alice)

        event = next(
            (
                e
                for e in tx.events
                if isinstance(e, self.withdrawal_queue.WithdrawalClaimed)
            ),
            None,
        )
        assert event is not None
        assert event.requestId == claim_id

        # since withdrawal queue is out of scope
        self.balances[alice] += event.amountOfETH

        logger.info(f"Alice claimed withdrawal of {claim_id}")

    """
        Accounting Oracle flows
    """

    #
    # Function:     submitReportExtraDataList, submitReportExtraDataEmpty
    # Caller:       AccountingOracle.SUBMIT_DATA_ROLE
    # Description:  submit stuck validator and exited validator data for each staking module by chunks with acending order
    # Status:       DONE
    #
    @invariant()
    def flow_submit_extra_data(self):
        if (
            self.beacon_chain.current_frame_index
            not in self.extra_data_submission_state
        ):
            return

        frame = self.beacon_chain.current_frame_index
        extra_submission_state: ExtraSubmissionState = self.extra_data_submission_state[
            frame
        ]

        # extrad data submission completed
        if extra_submission_state.complete == True:
            return

        if random.random() > 0.1:
            return

        if len(extra_submission_state.extra_data_chunk) == 0:
            # when no extra data

            tx = self.ao.submitReportExtraDataEmpty(from_=self.report_submitter)
            e = next(
                (
                    e
                    for e in tx.events
                    if isinstance(e, AccountingOracle.ExtraDataSubmitted)
                ),
                None,
            )
            assert e is not None

            for no_id in self.nor_ids:
                self.staking_modules[no_id].reward_distribution_state = (
                    NodeOperatorsRegistryMigrated.RewardDistributionState.ReadyForDistribution
                )
            extra_submission_state.complete = True

            logger.info(f"Submit extra data chunk empty for report")

            for sm in self.staking_modules.values():
                if sm.id in self.nor_ids:
                    sm.reward_distribution_state = (
                        NodeOperatorsRegistryMigrated.RewardDistributionState.ReadyForDistribution
                    )

                    assert (
                        sm.total_exited_keys_count == sm.total_exited_keys_count_in_sr
                    )

            return

        chunk = extra_submission_state.extra_data_chunk[
            extra_submission_state.submit_index
        ]
        items = chunk.items
        chunk_bytes = bytes(chunk)

        depositable_before = {}

        for item in items:
            if (item.module_id not in self.nor_ids) and item.item_type == 1:
                # stuck validator in csm
                for id in item.node_op_ids:
                    depositable_before[id] = (
                        self.csms[item.module_id]
                        .module.getNodeOperator(id)
                        .depositableValidatorsCount
                    )

        tx = self.ao.submitReportExtraDataList(
            chunk_bytes,
            from_=self.report_submitter,
        )

        stuck_events = [
            e
            for e in tx.events
            if isinstance(e, NodeOperatorsRegistryMigrated.StuckPenaltyStateChanged)
        ]
        stuck_csm_events = [
            e for e in tx.events if isinstance(e, CSModule.StuckSigningKeysCountChanged)
        ]

        exit_events = [
            e
            for e in tx.events
            if isinstance(
                e, NodeOperatorsRegistryMigrated.ExitedSigningKeysCountChanged
            )
        ]

        if TEST_OLD_SOLIDITY:
            exit_events = []
            for event in tx.raw_events:
                if (
                    event.topics[0]
                    == NodeOperatorsRegistryMigrated.ExitedSigningKeysCountChanged.selector
                ):
                    no_id = abi.decode(event.topics[1], [uint256])
                    exited_validators_count = abi.decode(event.data, [uint256])
                    exit_events.append(
                        NodeOperatorsRegistryMigrated.ExitedSigningKeysCountChanged(
                            no_id, exited_validators_count
                        )
                    )

        exit_csm_events = [
            e
            for e in tx.events
            if isinstance(e, CSModule.ExitedSigningKeysCountChanged)
        ]

        for item in items:
            if item.item_type != self.ao.EXTRA_DATA_TYPE_STUCK_VALIDATORS():
                continue
            id = item.module_id
            if id in self.nor_ids:
                self.staking_modules[id].nonce += 1
            else:
                self.csms[id].nonce += 1

            for i in range(item.node_ops_count):
                sm = self.staking_modules[id]

                if id in self.nor_ids:
                    event = next(
                        (
                            e
                            for e in stuck_events
                            if e.nodeOperatorId == item.node_op_ids[i]
                            and e.stuckValidatorsCount == item.validators_counts[i]
                        ),
                        None,
                    )  # common variable name
                    # Remove the event element from the events list if it exists
                    no = sm.node_operators[item.node_op_ids[i]]
                    if no.stuck_keys_count == item.validators_counts[i]:
                        # no event generated
                        pass
                    else:
                        if event is not None:
                            stuck_events.remove(event)
                        assert event is not None
                        assert isinstance(
                            event,
                            NodeOperatorsRegistryMigrated.StuckPenaltyStateChanged,
                        )
                        assert event.nodeOperatorId == item.node_op_ids[i]
                        assert event.stuckValidatorsCount == item.validators_counts[i]
                        assert no.refunded_keys_count == event.refundedValidatorsCount

                        if (
                            item.validators_counts[i] <= no.refunded_keys_count
                            and no.stuck_keys_count > no.refunded_keys_count
                        ):
                            assert (
                                event.stuckPenaltyEndTimestamp
                                == chain.blocks["latest"].timestamp
                                + self.staking_modules[id].stuck_penalty_delay
                            )
                            no.stuck_penalty_end_timestamp = (
                                event.stuckPenaltyEndTimestamp
                            )

                        no.stuck_keys_count = item.validators_counts[i]
                        self.update_summary_max_validators_count(no, id)

                elif self.staking_modules[id].is_csm:
                    event = next(
                        (
                            e
                            for e in stuck_csm_events
                            if e.nodeOperatorId == item.node_op_ids[i]
                            and e.stuckKeysCount == item.validators_counts[i]
                        ),
                        None,
                    )
                    no = self.csms[id].node_operators[item.node_op_ids[i]]

                    if no.stuck_keys_count == item.validators_counts[i]:
                        pass

                    else:
                        if event is not None:
                            stuck_csm_events.remove(event)
                        assert event is not None
                        assert isinstance(event, CSModule.StuckSigningKeysCountChanged)
                        assert event.nodeOperatorId == item.node_op_ids[i]
                        assert event.stuckKeysCount == item.validators_counts[i]
                        no.stuck_keys_count = item.validators_counts[i]

                        self._reenqueue(self.csms[id], no.id, depositable_before[no.id])

        # for each staking modules
        for item in items:
            if item.item_type != self.ao.EXTRA_DATA_TYPE_EXITED_VALIDATORS():
                continue
            # for each node operators
            id = item.module_id

            if id in self.nor_ids:
                self.staking_modules[id].nonce += 1
            else:
                self.csms[id].nonce += 1
            for i in range(item.node_ops_count):

                if id in self.nor_ids:
                    event = next(
                        (
                            e
                            for e in exit_events
                            if e.nodeOperatorId == item.node_op_ids[i]
                            and e.exitedValidatorsCount == item.validators_counts[i]
                        ),
                        None,
                    )
                    # Remove the event element from the events list if it exists
                    sm = self.staking_modules[id]
                    no = sm.node_operators[item.node_op_ids[i]]

                    if no.exited_keys_count == item.validators_counts[i]:
                        # no event generated
                        pass
                    else:
                        if event is not None:
                            exit_events.remove(event)

                        assert event is not None
                        assert isinstance(
                            event,
                            NodeOperatorsRegistryMigrated.ExitedSigningKeysCountChanged,
                        )
                        assert event.nodeOperatorId == item.node_op_ids[i]
                        assert event.exitedValidatorsCount == item.validators_counts[i]

                        sm.total_exited_keys_count += (
                            item.validators_counts[i] - no.exited_keys_count
                        )

                        for j in range(no.exited_keys_count, item.validators_counts[i]):
                            assert no.keys[j].key_state == KeyState.Deposited
                            no.keys[j].key_state = KeyState.Exited
                        no.exited_keys_count = item.validators_counts[i]

                        self.update_summary_max_validators_count(no, id)

                elif self.staking_modules[id].is_csm:
                    # different sm data structure is used
                    sm = self.csms[id]
                    event = next(
                        (
                            e
                            for e in exit_csm_events
                            if e.nodeOperatorId == item.node_op_ids[i]
                            and e.exitedKeysCount == item.validators_counts[i]
                        ),
                        None,
                    )
                    no = sm.node_operators[item.node_op_ids[i]]
                    if no.exited_keys_count == item.validators_counts[i]:
                        pass
                    else:
                        if event is not None:
                            exit_csm_events.remove(event)
                        assert event is not None
                        assert isinstance(event, CSModule.ExitedSigningKeysCountChanged)
                        assert event.nodeOperatorId == item.node_op_ids[i]
                        assert event.exitedKeysCount == item.validators_counts[i]

                        sm.total_exited_keys_count += (
                            item.validators_counts[i] - no.exited_keys_count
                        )

                        for j in range(no.exited_keys_count, item.validators_counts[i]):
                            assert no.keys[j].key_state == KeyState.Deposited
                            no.keys[j].key_state = KeyState.Exited
                        no.exited_keys_count = item.validators_counts[i]

        extra_submission_state.submit_index += 1

        logger.info(
            f"Submit extra data chunk #{extra_submission_state.submit_index}/{len(extra_submission_state.extra_data_chunk)} for report"
        )

        # end of extra data submission
        if (
            len(extra_submission_state.extra_data_chunk)
            == extra_submission_state.submit_index
        ):
            ret: AccountingOracle.ProcessingState = self.ao.getProcessingState()
            assert ret.mainDataSubmitted == True
            assert ret.extraDataSubmitted == True

            extra_submission_state.complete = True

            for i in self.nor_ids:
                sm = self.staking_modules[i]
                sm.reward_distribution_state = (
                    NodeOperatorsRegistryMigrated.RewardDistributionState.ReadyForDistribution
                )
                assert sm.total_exited_keys_count == sm.total_exited_keys_count_in_sr

    #
    # Function:     HashConsensus.submitReport and ValidatorExitBusOracle.submitReportData
    # Caller:       quarum member, report_submitter
    # Description:  KAPI decide which node validator to exit according to the state of withdrawal queue, and Ejector look at ValidatorsExitBusOracle.ValidatorExitReques event and does VEM. this exit request result submit to accounting oracle
    #               # KAPI select which node validator to exit according to the state of withdrawal queue
    #               For the testing, it does not effect staking module state, so I test the state in this contract
    #               https://hackmd.io/@lido/BJXRTxMRp#Exit-Order:~:text=Adding%20a%20new%20mode%20does%20not%20affect%20the%20overall%20limit%20on%20validator%20exits%20per%20report.%20If%20it%20is%20necessary%20to%20accelerated%20exit%20a%20large%20number%20of%20validators%2C%20this%20will%20be%20done%20over%20several%20reports.
    #
    # Status:       Done
    #

    @invariant()
    def invariant_vebo(self):
        submit_frame_index = self.beacon_chain.current_frame_index
        if (
            submit_frame_index in self.vebo_report_submission
            and self.vebo_report_submission[submit_frame_index] == True
        ):
            return

        index = 0

        vebo_datas: List[VEBOData] = []
        vebo_bytes = b""
        for sm in self.staking_modules.values():
            nos = sm.node_operators
            if len(nos) == 0:
                continue

            sel_nos, sel_nos_ids, key_indexes = (
                self.random_node_operators_and_keys_count_array("exit_request", nos)
            )

            for i in range(len(sel_nos_ids)):

                no = sm.node_operators[sel_nos_ids[i]]

                if key_indexes[i] == 0:
                    continue
                vebo_data = VEBOData(
                    module_id=sm.id,
                    node_id=sel_nos_ids[i],
                    validator_index=key_indexes[i],
                    public_key=no.keys[key_indexes[i] - 1].pkey,  # first
                )
                vebo_datas.append(vebo_data)

        for vebo_data in vebo_datas:
            vebo_bytes += bytes(vebo_data)
            assert len(bytes(vebo_data)) == 64

        vebo_report = ValidatorsExitBusOracle.ReportData(
            consensusVersion=2,
            refSlot=self.beacon_chain.current_frame.reference_slot,
            requestsCount=len(vebo_datas),
            dataFormat=self.vebo.DATA_FORMAT_LIST(),
            data=vebo_bytes,
        )
        report_hash = keccak256(abi.encode(vebo_report))

        tx = self.hc_vebo.submitReport(
            slot=self.beacon_chain.current_frame.reference_slot,
            report=report_hash,
            consensusVersion=2,
            from_=self.quaram_member,
        )

        event = next(
            (e for e in tx.events if isinstance(e, HashConsensus.ConsensusReached)),
            None,
        )
        assert event is not None
        tx = self.vebo.submitReportData(
            vebo_report, uint256(1), from_=self.report_submitter
        )

        events = [
            e
            for e in tx.events
            if isinstance(e, ValidatorsExitBusOracle.ValidatorExitRequest)
        ]

        for index, event in enumerate(events):
            assert event.validatorPubkey == vebo_datas[index].public_key
            logger.debug(f"ValidatorExitRequest to {vebo_datas[index].public_key}")

        for req in vebo_datas:
            self.staking_modules[req.module_id].node_operators[
                req.node_id
            ].exit_requested_key_count += 1

        self.vebo_report_submission[submit_frame_index] = True
        logger.info(f"VEBO report submitted")

        self.invariant_check_staking_module_summary()

    #
    # Function:     HashConsensus.submitReport and AccountingOracle.submitReportData
    # Caller:       quarum member, report_submitter
    # Description:  submit the reort
    # Status:       Done
    #

    @invariant()
    def flow_submit_report(self):

        submit_frame_index = self.beacon_chain.current_frame_index

        if (
            submit_frame_index in self.main_report_sumission
            and self.main_report_sumission[submit_frame_index] == True
        ):
            return

        keys_list = list(self.main_report_sumission.keys())
        # Check if there are at least two keys
        if len(keys_list) > 1:
            second_added_key = keys_list[-1]
        else:
            second_added_key = None

        if second_added_key == 0:
            second_added_key = None

        if (
            second_added_key in self.extra_data_submission_state
            and self.extra_data_submission_state[second_added_key].complete == False
        ):
            logger.warning(f"extra data for previous frame not completed yet")
            logger.warning(
                f"We stop the fuzz test since it should done extra data submission before next report submission or fix by unsafe function"
            )
            assert False

        assert submit_frame_index - 1 in self.refslot_data
        ref_data = self.refslot_data[submit_frame_index - 1]

        no_stuck_submision = random.random() < 0.8
        no_exit_submission = random.random() < 0.8

        staking_module_ids = []
        report_exited_validators = []
        items: List[ExtraDataItem] = []

        index = 0

        # # stucked key count part
        stuck_temps = {}

        if not no_stuck_submision:
            for sm in self.staking_modules.values():

                # if it is NOR
                nos = sm.node_operators

                # if it is CSM
                if sm.is_csm:
                    assert len(nos) == 0
                    nos = self.csms[sm.id].node_operators

                if len(nos) == 0:
                    continue

                _, sel_nos_ids, key_counts, stuck_temp = (
                    self.random_node_operators_and_keys_count_array_for_stuck(nos)
                )
                if sum(key_counts) == 0:
                    continue
                stuck_temps[sm.id] = stuck_temp
                item = ExtraDataItem(
                    index=index,
                    item_type=self.ao.EXTRA_DATA_TYPE_STUCK_VALIDATORS(),
                    module_id=sm.id,
                    node_ops_count=len(sel_nos_ids),
                    node_op_ids=sel_nos_ids,
                    validators_counts=key_counts,
                )

                items.append(item)
                index += 1

        logger.debug(f"Stucked keys count: {len(items)}")
        debug_stucked_keys = len(items)

        if not no_exit_submission:
            # exit key precalculation part
            for sm in self.staking_modules.values():

                # if it is NOR
                nos = sm.node_operators

                # if it is CSM
                if sm.is_csm:
                    assert len(nos) == 0
                    nos = self.csms[sm.id].node_operators

                if len(nos) == 0:
                    continue

                arg = {}
                if sm.id in stuck_temps:
                    arg = stuck_temps[sm.id]

                _, sel_nos_ids, key_counts = (
                    self.random_node_operators_and_keys_count_array_for_exit(nos, arg)
                )
                if sum(key_counts) == 0:
                    continue
                item = ExtraDataItem(
                    index=index,
                    item_type=self.ao.EXTRA_DATA_TYPE_EXITED_VALIDATORS(),
                    module_id=sm.id,
                    node_ops_count=len(sel_nos_ids),
                    node_op_ids=sel_nos_ids,
                    validators_counts=key_counts,
                )
                sum_exited_varidators = 0
                for no in nos.values():
                    if no.id not in sel_nos_ids:
                        sum_exited_varidators += no.exited_keys_count

                staking_module_ids.append(sm.id)
                report_exited_validators.append(sum(key_counts) + sum_exited_varidators)

                assert sm.total_deposited_keys_count >= sum(key_counts)

                items.append(item)
                index += 1
        logger.debug(f"Exited keys count: {len(items) - debug_stucked_keys}")

        total_items_in_report: List[ExtraDataItem] = items
        extra_data: List[ExtraDataChunk] = []
        while len(items) != 0:
            length = random_int(1, len(items))
            partial_items = items[:length]
            items = items[length:]

            extra_data_chunk = ExtraDataChunk(next_hash=bytes32(0), items=partial_items)
            extra_data.append(extra_data_chunk)

        for i in reversed(range(len(extra_data))):
            if i == 0:
                break
            extra_data[i - 1].next_hash = keccak256(bytes(extra_data[i]))

        if len(total_items_in_report) != 0:
            extra_data_format = 1
            extra_data_hash = keccak256(bytes(extra_data[0]))
            extra_data[-1].next_hash = bytes32(0)
            extra_data_items_count = len(total_items_in_report)
        else:
            extra_data_format = 0
            extra_data_hash = bytes32(0)
            extra_data_items_count = 0

        # https://docs.lido.fi/guides/oracle-operator-manual
        # Accounting Oracle and VEBO are submitting individually the order does not matter

        pre_total_shares = LIDO.getTotalShares()
        pre_total_pooled_eth = LIDO.getTotalPooledEther()

        pre_cl_validator = self.lido_beacon_state.beacon_validators
        pre_cl_balance = self.lido_beacon_state.beacon_balance

        post_cl_validator = pre_cl_validator
        if submit_frame_index - 1 in self.deposited_inc_in_frame:
            post_cl_validator += self.deposited_inc_in_frame[submit_frame_index - 1]

        pre_cl_balance += (post_cl_validator - pre_cl_validator) * 32 * 10**18
        post_cl_balance = pre_cl_balance

        if random_bool():
            post_cl_balance += random_int(0, 100) * 10**9

        report_cl_balance = post_cl_balance // 10**9

        token_rebase_limitter: TokenRebaseLimiterData = TokenRebaseLimiterData(
            0, 0, 0, 0, 0
        )

        # initLimiterState
        oracle_getMaxPositiveTokenRebase = (
            self.sanity_ckecker.getMaxPositiveTokenRebase()
        )

        if (
            oracle_getMaxPositiveTokenRebase == 0
            or oracle_getMaxPositiveTokenRebase > uint64.max
        ):
            logger.critical(f"should be revert")

        if pre_total_pooled_eth == 0:
            oracle_getMaxPositiveTokenRebase = uint64.max

        token_rebase_limitter.currentTotalPooledEther = pre_total_pooled_eth
        token_rebase_limitter.preTotalPooledEther = pre_total_pooled_eth
        token_rebase_limitter.preTotalShares = pre_total_shares
        token_rebase_limitter.positiveRebaseLimit = oracle_getMaxPositiveTokenRebase

        if oracle_getMaxPositiveTokenRebase == uint64.max:
            token_rebase_limitter.maxTotalPooledEther = uint256.max
        else:
            token_rebase_limitter.maxTotalPooledEther = (
                pre_total_pooled_eth
                + (oracle_getMaxPositiveTokenRebase * pre_total_pooled_eth) // 10**9
            )

        if token_rebase_limitter.maxTotalPooledEther != uint64.max:
            if post_cl_balance < pre_cl_balance:
                decrease_amount = pre_cl_balance - post_cl_balance
                token_rebase_limitter.currentTotalPooledEther -= decrease_amount
            else:
                increase_amount = post_cl_balance - pre_cl_balance
                token_rebase_limitter.currentTotalPooledEther = (
                    pre_total_pooled_eth + increase_amount
                )
                if (
                    token_rebase_limitter.currentTotalPooledEther
                    > token_rebase_limitter.maxTotalPooledEther
                ):
                    token_rebase_limitter.currentTotalPooledEther = (
                        token_rebase_limitter.maxTotalPooledEther
                    )

        def increase_till_max_ret_changes(
            amount: int, max_amount: int, addition: int
        ) -> Tuple[int, int]:
            prev_amount = amount
            amount = min(amount + addition, max_amount)
            return amount - prev_amount, amount

        withdrawals, token_rebase_limitter.currentTotalPooledEther = (
            increase_till_max_ret_changes(
                token_rebase_limitter.currentTotalPooledEther,
                token_rebase_limitter.maxTotalPooledEther,
                ref_data.withdrawalVaultBalance,
            )
        )

        el_rewards, token_rebase_limitter.currentTotalPooledEther = (
            increase_till_max_ret_changes(
                token_rebase_limitter.currentTotalPooledEther,
                token_rebase_limitter.maxTotalPooledEther,
                ref_data.elRewardsVaultBalance,
            )
        )

        distribute_rewards = False
        # _processRewards
        post_cl_total_balance = post_cl_balance + withdrawals

        py_recipants = []
        py_module_ids = []
        py_module_fees = []
        py_total_fee = 0

        if post_cl_total_balance > pre_cl_balance:
            cnsensus_layer_rewards = post_cl_total_balance - pre_cl_balance

            py_precision_points = FEE_PRECISION_POINTS
            total_active_validators = 0
            for sm in self.staking_modules.values():
                exited_count = sm.total_exited_keys_count_in_sr
                if (
                    sm.id in staking_module_ids
                ):  # which mean updated in the report only in sr
                    exited_count = report_exited_validators[
                        staking_module_ids.index(sm.id)
                    ]
                total_active_validators += sm.total_deposited_keys_count - exited_count

            for sm in self.staking_modules.values():
                exited_count = sm.total_exited_keys_count_in_sr
                if (
                    sm.id in staking_module_ids
                ):  # which mean updated in the report only in sr
                    exited_count = report_exited_validators[
                        staking_module_ids.index(sm.id)
                    ]
                active_validator_count = sm.total_deposited_keys_count - exited_count
                if active_validator_count == 0:
                    continue
                py_module_ids.append(sm.id)
                py_recipants.append(self.deployed_staking_modules[sm.id].address)
                sm_validators_share = (
                    active_validator_count * FEE_PRECISION_POINTS
                ) // total_active_validators
                module_fee = (
                    sm_validators_share * sm.staking_module_fee
                ) // TOTAL_BASIS_POINTS
                if (
                    self.sr.getStakingModuleStatus(sm.id)
                    != StakingRouter.StakingModuleStatus.Stopped
                ):
                    py_module_fees.append(module_fee)
                else:
                    py_module_fees.append(0)

                py_total_fee += (
                    (sm_validators_share * sm.treasury_fee) // TOTAL_BASIS_POINTS
                ) + module_fee

            if py_total_fee > 0:
                module_reward = [0] * len(py_recipants)
                total_reward = cnsensus_layer_rewards + el_rewards

                total_pooled_eth_with_rewards = pre_total_pooled_eth + total_reward

                sharesMintedAsFees = (
                    total_reward * py_total_fee * pre_total_shares
                ) // (
                    (total_pooled_eth_with_rewards * py_precision_points)
                    - (total_reward * py_total_fee)
                )
                distribute_rewards = True
                for i in range(len(py_recipants)):
                    module_reward[i] = (
                        sharesMintedAsFees * py_module_fees[i]
                    ) // py_total_fee

        simulated_share_rate = int(random.uniform(0, 1000) * 10**17)
        (ether_to_lock, _) = (0, 0)
        if self.withdraw_request_ids[2] != [] and simulated_share_rate != 0:
            # withdrawal queue is out of scope so use view function
            (ether_to_lock, _) = self.withdrawal_queue.prefinalize(
                self.withdraw_request_ids[2], simulated_share_rate
            )

        bunker_mode = random_bool()
        report_data = AccountingOracle.ReportData(
            consensusVersion=2,
            refSlot=self.beacon_chain.current_frame.reference_slot,
            numValidators=post_cl_validator,
            clBalanceGwei=report_cl_balance,
            stakingModuleIdsWithNewlyExitedValidators=staking_module_ids,
            numExitedValidatorsByStakingModule=report_exited_validators,
            withdrawalVaultBalance=ref_data.withdrawalVaultBalance,
            elRewardsVaultBalance=ref_data.elRewardsVaultBalance,
            sharesRequestedToBurn=ref_data.sharesRequestedToBurn,
            withdrawalFinalizationBatches=self.withdraw_request_ids[2],
            simulatedShareRate=simulated_share_rate,
            isBunkerMode=bunker_mode,
            extraDataFormat=extra_data_format,
            extraDataHash=extra_data_hash,
            extraDataItemsCount=extra_data_items_count,
        )

        report_hash = keccak256(abi.encode(report_data))

        tx = self.hc_ao.submitReport(
            slot=report_data.refSlot,
            report=report_hash,
            consensusVersion=2,
            from_=self.quaram_member,
        )

        self.wq_is_bunker_mode = bunker_mode

        assert self.beacon_chain.current_frame.reference_slot == report_data.refSlot

        event = next(
            (e for e in tx.events if isinstance(e, HashConsensus.ConsensusReached)),
            None,
        )
        assert event is not None

        tx = self.ao.submitReportData(
            report_data, uint256(2), from_=self.report_submitter
        )

        ret: AccountingOracle.ProcessingState = self.ao.getProcessingState()
        assert ret.mainDataSubmitted == True

        self.finalized_withdraw_request_ids += self.withdraw_request_ids[2]
        self.main_report_sumission[submit_frame_index] = True

        for i in range(len(staking_module_ids)):
            self.staking_modules[
                staking_module_ids[i]
            ].total_exited_keys_count_in_sr = report_exited_validators[i]

        logger.info(f"Report submitted {len(extra_data)} of extra data")

        for id, sm in self.deployed_staking_modules.items():
            logger.debug(f"{id} balance of stETH: {LIDO.balanceOf(sm.address)}")

        for i in reversed(range(1, 3)):
            ## using data queue to aboid IncorrectRequestFinalization()
            self.withdraw_request_ids[i] = self.withdraw_request_ids[i - 1]
        self.withdraw_request_ids[0] = []

        # reward value calculation
        if distribute_rewards:
            for i in range(len(py_module_ids)):

                id = py_module_ids[i]

                if module_reward[i] != 0:
                    event = next(
                        (
                            e
                            for e in tx.events
                            if isinstance(e, LidoMigrated.TransferShares)
                            and e.to == py_recipants[i]
                        ),
                        None,
                    )
                    assert event is not None
                    assert abs(event.sharesValue - module_reward[i]) < 10
                    if not self.staking_modules[id].is_csm:
                        self.staking_modules[id].reward_distribution_state = (
                            NodeOperatorsRegistryMigrated.RewardDistributionState.TransferredToModule
                        )

                    if self.staking_modules[id].is_csm:
                        sm = self.csms[id]
                        # for csm, rewards transfered to fee distributor by csm module
                        self.shares[sm.fee_distributor] += event.sharesValue

                    if id in self.nor_ids:
                        # for nor, rewards transfered to nor
                        self.shares[self.nors[id]] += event.sharesValue

        self.lido_beacon_state.beacon_validators = post_cl_validator
        self.lido_beacon_state.beacon_balance = report_cl_balance * 10**9

        for id in self.nor_ids:
            assert (
                self.staking_modules[id].reward_distribution_state
                == self.nors[id].getRewardDistributionState()
            )

        self.extra_data_submission_state[submit_frame_index] = ExtraSubmissionState(
            complete=False, extra_data_chunk=extra_data, submit_index=0
        )

        if el_rewards > 0:
            event = next(
                (e for e in tx.events if isinstance(e, LidoMigrated.ELRewardsReceived)),
                None,
            )
            assert event is not None
            assert event.amount == el_rewards
            self.balances[EL_REWARDS_VAULT] -= el_rewards
            self.balances[LIDO] += el_rewards

        assert self.balances[EL_REWARDS_VAULT] >= 0

        if withdrawals > 0:
            event = next(
                (
                    e
                    for e in tx.events
                    if isinstance(e, LidoMigrated.WithdrawalsReceived)
                ),
                None,
            )
            assert event is not None
            assert event.amount == withdrawals
            self.balances[WITHDRAWAL_VAULT] -= withdrawals
            self.balances[LIDO] += withdrawals

        assert self.balances[WITHDRAWAL_VAULT] >= 0
        self.balances[LIDO] -= ether_to_lock

        state: AccountingOracle.ProcessingState = self.ao.getProcessingState()

        if len(extra_data) != 0:
            assert 1 == state.extraDataFormat
        else:
            assert 0 == state.extraDataFormat

    @invariant()
    def invariant_store_reporting_state(self):

        if random.random() < 0.01:
            # exited validator withdraws to withdrawal vault according to withdrawal credential
            amount = random_int(15 * 10**18, 32 * 10**19)
            WITHDRAWAL_VAULT.balance += amount
            self.balances[WITHDRAWAL_VAULT] += amount

        if random.random() < 0.01:
            amount = random_int(0, 10**14)
            EL_REWARDS_VAULT.balance += amount
            self.balances[EL_REWARDS_VAULT] += amount

        self.refslot_data[self.beacon_chain.current_frame_index] = RefslotData(
            available=True,
            withdrawalVaultBalance=WITHDRAWAL_VAULT.balance,
            elRewardsVaultBalance=EL_REWARDS_VAULT.balance,
            sharesRequestedToBurn=BURNER.getSharesRequestedToBurn()[0],
        )

    @invariant()
    def invariant_balances(self):
        for csm in self.csms.values():
            # usually zero
            assert self.balances[csm.module] == self.csms_initial_balance[csm.module]

        for nor in self.nors.values():
            assert self.balances[nor] == 0
        for acc, balance in self.balances.items():
            assert acc.balance == balance

    @invariant()
    def invariant_shares(self):
        for csm in self.csms.values():
            assert self.shares[csm.module] == 0

        for acc, shares in self.shares.items():
            assert LIDO.sharesOf(acc) == shares

    """
        Node Operator Registry invariants
    """

    # nor specific key count relation check
    @invariant()
    def invariant_no_keys(self) -> None:
        for id in self.nor_ids:
            for no in self.staking_modules[id].node_operators.values():
                assert 0 <= no.exited_keys_count <= no.deposited_keys_count
                assert no.deposited_keys_count <= no.vetted_keys_count
                assert no.vetted_keys_count <= no.total_keys_count
                assert no.stuck_keys_count <= (
                    no.deposited_keys_count - no.exited_keys_count
                )

    # NOR specific check
    @invariant()
    def invariant_check_python_state(self) -> None:

        for id in self.nor_ids:

            total_exited_key_state = 0
            total_deposited_keys_state = 0
            total_depositable_keys_state = 0
            for no in self.staking_modules[id].node_operators.values():
                (
                    target_limit_mode,
                    target_validators_count,
                    stuck_validators_count,
                    refunded_validators_count,
                    stack_penalty_end_timestamp,
                    total_exited_validators_count,
                    total_deposited_validators_count,
                    depositable_validators_count,
                ) = self.nors[id].getNodeOperatorSummary(no.id)
                assert (
                    target_limit_mode == no.target_limit_mode
                )  # TARGET_LIMIT_MODE_OFFSET
                assert (
                    target_validators_count == no.target_limit
                )  # TARGET_VALIDATORS_COUNT_OFFSET
                assert (
                    stuck_validators_count == no.stuck_keys_count
                )  # STUCK_VALIDATORS_COUNT_OFFSET
                assert (
                    refunded_validators_count == no.refunded_keys_count
                )  # REFUNDED_VALIDATORS_COUNT_OFFSET
                assert (
                    stack_penalty_end_timestamp == no.stuck_penalty_end_timestamp
                )  # STUCK_PENALTY_END_TIMESTAMP_OFFSET
                assert (
                    total_exited_validators_count == no.exited_keys_count
                )  # TOTAL_EXITED_VALIDATORS_OFFSET
                assert (
                    total_deposited_validators_count == no.deposited_keys_count
                )  # TOTAL_DEPOSITED_KEYS_COUNT_OFFSET
                assert (
                    depositable_validators_count
                    == no.max_keys_count - no.deposited_keys_count
                )  # MAX_VALIDATORS_COUNT_OFFSET

                logger.debug(
                    f"nor: {id} no: {no.id} active: {self.nors[id].getNodeOperator(no.id, False)[0]} exited: {no.exited_keys_count} refund: {no.refunded_keys_count} stuck: {no.stuck_keys_count} deposited: {no.deposited_keys_count} vet: {no.vetted_keys_count}  total: {no.total_keys_count}"
                )

                (
                    active,
                    name,
                    reward_address,
                    total_vetted_validators_count,
                    total_exited_validators_count,
                    total_added_validators_count,
                    total_deposited_validators_count,
                ) = self.nors[id].getNodeOperator(no.id, True)
                assert active == no.active
                assert name == no.name
                assert reward_address == no.rewards_account
                assert (
                    total_vetted_validators_count == no.vetted_keys_count
                )  # TOTAL_VETTED_KEYS_COUNT_OFFSET
                assert (
                    total_exited_validators_count == no.exited_keys_count
                )  # TOTAL_EXITED_KEYS_COUNT_OFFSET
                assert (
                    total_added_validators_count == no.total_keys_count
                )  # TOTAL_KEYS_COUNT_OFFSET
                assert (
                    total_deposited_validators_count == no.deposited_keys_count
                )  # TOTAL_DEPOSITED_KEYS_COUNT_OFFSET

                assert len(no.keys) == no.total_keys_count

                total_exited_key_state += no.exited_keys_count
                total_deposited_keys_state += no.deposited_keys_count
                total_depositable_keys_state += (
                    no.max_keys_count - no.deposited_keys_count
                )

                for i in range(no.total_keys_count):
                    (pubkey, signature, used) = self.nors[id].getSigningKey(no.id, i)
                    assert pubkey == no.keys[i].pkey
                    assert signature == no.keys[i].signature

                for i in range(no.vetted_keys_count, no.total_keys_count):
                    assert no.keys[i].key_state == KeyState.Added

                for i in range(no.deposited_keys_count, no.vetted_keys_count):
                    assert no.keys[i].key_state == KeyState.Vetted

                for i in range(
                    no.exited_keys_count + no.stuck_keys_count, no.deposited_keys_count
                ):
                    assert no.keys[i].key_state == KeyState.Deposited

                if no.exited_keys_count > 0:
                    for i in range(0, no.exited_keys_count):
                        assert no.keys[i].key_state == KeyState.Exited

            (
                total_exited_validators,
                total_deposited_validators,
                depositable_validators,
            ) = self.deployed_staking_modules[id].getStakingModuleSummary()
            assert (
                self.staking_modules[id].total_exited_keys_count
                == total_exited_validators
            )
            assert (
                self.staking_modules[id].total_deposited_keys_count
                == total_deposited_validators
            )
            assert (
                self.staking_modules[id].total_depostable_keys_count
                == depositable_validators
            )
            assert (
                self.staking_modules[id].reward_distribution_state
                == self.nors[id].getRewardDistributionState()
            )

            assert (
                self.staking_modules[id].stuck_penalty_delay
                == self.nors[id].getStuckPenaltyDelay()
            )

            # in python state check
            assert total_exited_validators == total_exited_key_state
            assert total_deposited_validators == total_deposited_keys_state
            assert total_depositable_keys_state == total_depositable_keys_state

    @invariant()
    def invariant_rewarded_value(self) -> None:
        for id in self.nor_ids:
            for no in self.staking_modules[id].node_operators.values():
                assert no.rewards_account_share == LIDO.sharesOf(no.rewards_account)

    @invariant()
    def invariant_after_submit_extra_data_match_exited_count(self):
        if (
            self.beacon_chain.current_frame_index
            not in self.extra_data_submission_state
        ):
            return
        extra_submission_state: ExtraSubmissionState = self.extra_data_submission_state[
            self.beacon_chain.current_frame_index
        ]
        if extra_submission_state.complete == False:
            return
        for id in self.nor_ids:
            sm = self.staking_modules[id]
            staking_module_info = self.sr.getStakingModule(sm.id)
            (total_exited_validators, _, _) = self.deployed_staking_modules[
                id
            ].getStakingModuleSummary()
            assert (
                self.staking_modules[id].total_exited_keys_count
                == self.staking_modules[id].total_exited_keys_count_in_sr
            )

            assert staking_module_info.exitedValidatorsCount == total_exited_validators

    @invariant()
    def invariant_check_staking_module_summary(self) -> None:
        for i in self.staking_modules.keys():

            (
                total_exited_validators,
                total_deposited_validators,
                depositable_validators,
            ) = self.deployed_staking_modules[i].getStakingModuleSummary()

            logger.debug(
                f"sm: {i} is_csm: {self.staking_modules[i].is_csm} exited: {total_exited_validators} deposited: {total_deposited_validators} depositable: {depositable_validators} state: {self.staking_modules[i].reward_distribution_state}"
            )

            if self.staking_modules[i].is_csm:
                continue

            assert (
                self.staking_modules[i].total_exited_keys_count
                == total_exited_validators
            )
            assert (
                self.staking_modules[i].total_deposited_keys_count
                == total_deposited_validators
            )
            assert (
                self.staking_modules[i].total_depostable_keys_count
                == depositable_validators
            )  # depositable key count rule is different for CSM and NOR

            assert (
                self.staking_modules[i].active_node_operators
                == self.deployed_staking_modules[i].getActiveNodeOperatorsCount()
            )

    @invariant()
    def invariant_lido_beacon_state(self):
        (depositedValidators, beaconValidators, beaconBalance) = LIDO.getBeaconStat()

        assert self.lido_beacon_state.deposited_validators == depositedValidators
        assert self.lido_beacon_state.beacon_validators == beaconValidators
        assert self.lido_beacon_state.beacon_balance == beaconBalance

    """
        Deposit Security Module invariants
    """

    @invariant()
    def invariant_guardians(self) -> None:
        assert len(self.dsm_guardians) == len(self.dsm.getGuardians())
        assert self.dsm_quorum == self.dsm.getGuardianQuorum()

    """
        Staking Router invariants
    """

    @invariant()
    def invariant_sm_address(self):
        for sm in self.staking_modules.values():
            if sm.is_csm:
                assert (
                    self.sr.getStakingModule(sm.id).stakingModuleAddress
                    == self.csms[sm.id].module.address
                )

    @invariant()
    def invariant_staking_router_module_state(self):

        for i in self.nor_ids:
            sm = self.staking_modules[i]
            staking_module_info = self.sr.getStakingModule(sm.id)
            assert (
                staking_module_info.exitedValidatorsCount
                == sm.total_exited_keys_count_in_sr
            )
            assert sm.stake_share_limit == staking_module_info.stakeShareLimit
            if sm.id in self.nor_ids:
                assert staking_module_info.name == "NOR - Curated staking module"

    @invariant()
    def invariant_staking_modules(self) -> None:
        assert len(self.staking_modules) == self.sr.getStakingModulesCount()

    @invariant()
    def invariant_nonces(self) -> None:
        for sm in self.staking_modules.values():
            if sm.is_csm:
                assert (
                    IStakingModule(sm.staking_module.stakingModuleAddress).getNonce()
                    == self.csms[sm.id].nonce
                )
            else:
                assert (
                    IStakingModule(sm.staking_module.stakingModuleAddress).getNonce()
                    == sm.nonce
                )

    @invariant()
    def invariant_bond(self):
        t = chain.blocks["latest"].timestamp

        for csm in self.csms.values():
            for no in csm.node_operators.values():
                assert csm.accounting.getBondShares(no.id) == no.bond_shares
                assert csm.accounting.getLockedBondInfo(no.id) == CSAccounting.BondLock(
                    no.locked_bond, no.lock_expiry
                )
                assert self._get_actual_locked_bond(
                    no, t
                ) == csm.accounting.getActualLockedBond(no.id)

            assert csm.accounting.totalBondShares() == sum(
                no.bond_shares for no in csm.node_operators.values()
            )

    @invariant()
    def invariant_keys(self):
        with chain.snapshot_and_revert():
            for csm in self.csms.values():
                for no in csm.node_operators.values():
                    assert (
                        self._get_enqueued_keys(csm, no.id)
                        == csm.module.getNodeOperator(no.id).enqueuedCount
                    )

                    # workaround for an issue in contracts when depositableValidatorsCount is not updated after bond lock retention period end
                    csm.module.normalizeQueue(no.id, from_=random_account())

                t = chain.blocks["latest"].timestamp
                depositable_sum = 0
                deposited_sum = 0
                exited_sum = 0

                for no in csm.node_operators.values():

                    assert b"".join(no.keys_bytes) == csm.module.getSigningKeys(
                        no.id, 0, no.total_keys_count
                    )
                    assert (
                        b"".join(no.keys_bytes),
                        b"".join(no.signatures),
                    ) == csm.module.getSigningKeysWithSignatures(
                        no.id, 0, no.total_keys_count
                    )
                    info = csm.module.getNodeOperator(no.id)
                    assert (
                        self._get_depositable_keys(no, t)
                        == info.depositableValidatorsCount
                    )
                    assert no.total_keys_count == info.totalAddedKeys
                    assert no.withdrawn_keys == info.totalWithdrawnKeys
                    assert no.stuck_keys_count == info.stuckValidatorsCount
                    assert no.target_limit == info.targetLimit
                    assert no.target_limit_mode == info.targetLimitMode
                    assert no.manager.address == info.managerAddress
                    assert no.rewards_account.address == info.rewardAddress

                    assert (
                        no.deposited_keys + no.withdrawn_keys == info.totalDepositedKeys
                    )  # CSM counts withdrawn keys as deposited
                    assert no.exited_keys_count == info.totalExitedKeys
                    assert no.vetted_keys_count == info.totalVettedKeys
                    assert (
                        csm.module.getNodeOperatorNonWithdrawnKeys(no.id)
                        == no.total_keys_count - no.withdrawn_keys
                    )

                    # enqueued keys already checked before workaround

                    unbonded = (
                        no.total_keys_count
                        - no.withdrawn_keys
                        - self._get_keys_by_eth(no, t, False)
                    )
                    assert csm.accounting.getUnbondedKeysCountToEject(no.id) == max(
                        unbonded, 0
                    )
                    assert csm.accounting.getUnbondedKeysCount(no.id) == max(
                        no.total_keys_count
                        - no.withdrawn_keys
                        - self._get_keys_by_eth(no, t, True),
                        0,
                    )

                    for key in range(no.total_keys_count):
                        assert no.slashed[key] == csm.module.isValidatorSlashed(
                            no.id, key
                        )
                        assert no.withdrawn[key] == csm.module.isValidatorWithdrawn(
                            no.id, key
                        )

                    assert csm.accounting.getBondSummary(no.id) == (
                        LIDO.getPooledEthByShares(no.bond_shares),
                        self._get_total_bond(
                            no.total_keys_count - no.withdrawn_keys, no.bond_curve
                        )
                        + self._get_actual_locked_bond(no, t),
                    )
                    assert csm.accounting.getBondSummaryShares(no.id) == (
                        no.bond_shares,
                        LIDO.getSharesByPooledEth(
                            self._get_total_bond(
                                no.total_keys_count - no.withdrawn_keys, no.bond_curve
                            )
                            + self._get_actual_locked_bond(no, t)
                        ),
                    )

                    for i in range(no.total_keys_count):
                        pubkey = csm.module.getSigningKeys(no.id, i, 1)
                        assert pubkey == no.keys[i].pkey

                    for i in range(no.vetted_keys_count, no.total_keys_count):
                        assert no.keys[i].key_state == KeyState.Added

                    for i in range(no.deposited_keys_count, no.vetted_keys_count):
                        assert no.keys[i].key_state == KeyState.Vetted

                    for i in range(
                        no.exited_keys_count + no.stuck_keys_count,
                        no.deposited_keys_count,
                    ):
                        assert no.keys[i].key_state == KeyState.Deposited

                    if no.exited_keys_count > 0:
                        for i in range(0, no.exited_keys_count):
                            assert no.keys[i].key_state == KeyState.Exited
                    logger.debug(
                        f"csm: {csm.id} no: {no.id} exited: {info.totalExitedKeys} deposited: {info.totalDepositedKeys} depositable: {info.depositableValidatorsCount} vetted: {info.totalVettedKeys} total: {info.totalAddedKeys}"
                    )

                    summary = csm.module.getNodeOperatorSummary(no.id)
                    if (
                        unbonded
                        > no.total_keys_count - no.deposited_keys - no.withdrawn_keys
                    ):
                        target_limit_mode = 2
                        if no.target_limit_mode == 2:
                            target_limit = min(
                                no.target_limit,
                                no.total_keys_count - no.withdrawn_keys - unbonded,
                            )
                        else:
                            target_limit = (
                                no.total_keys_count - no.withdrawn_keys - unbonded
                            )
                    else:
                        target_limit_mode = no.target_limit_mode
                        target_limit = no.target_limit
                    assert summary == (
                        target_limit_mode,
                        target_limit,
                        no.stuck_keys_count,
                        0,
                        0,
                        no.exited_keys_count,
                        no.deposited_keys + no.withdrawn_keys,
                        self._get_depositable_keys(no, t),
                    )

                    depositable_sum += info.depositableValidatorsCount
                    deposited_sum += info.totalDepositedKeys
                    exited_sum += info.totalExitedKeys

                    for key in range(no.total_keys_count):
                        assert no.slashed[key] == csm.module.isValidatorSlashed(
                            no.id, key
                        )
                        assert no.withdrawn[key] == csm.module.isValidatorWithdrawn(
                            no.id, key
                        )

                    assert csm.accounting.getBondSummary(no.id) == (
                        LIDO.getPooledEthByShares(no.bond_shares),
                        self._get_total_bond(
                            no.total_keys_count - no.withdrawn_keys, no.bond_curve
                        )
                        + self._get_actual_locked_bond(no, t),
                    )
                    assert csm.accounting.getBondSummaryShares(no.id) == (
                        no.bond_shares,
                        LIDO.getSharesByPooledEth(
                            self._get_total_bond(
                                no.total_keys_count - no.withdrawn_keys, no.bond_curve
                            )
                            + self._get_actual_locked_bond(no, t)
                        ),
                    )

                assert csm.module.getStakingModuleSummary() == (
                    exited_sum,
                    deposited_sum,
                    depositable_sum,
                )

    @invariant()
    def invariant_queue(self):
        for csm in self.csms.values():
            head, tail = csm.module.depositQueue()
            current = head
            i = 0

            while current != tail:
                item = csm.module.depositQueueItem(current)
                no_id = item >> (256 - 64)
                keys_count = item >> (256 - 64 - 64) & (2**64 - 1)

                assert csm.queue[i] == QueueItem(no_id, keys_count)

                current = item & (2**128 - 1)
                i += 1

            assert csm.module.depositQueueItem(tail) == 0
            assert len(csm.queue) == i

    # not used in general fuzzer run
    # @invariant()
    def invariant_all_withdrawn(self):
        for csm in self.csms.values():
            with chain.snapshot_and_revert():
                chain.mine(lambda t: t + csm.bond_lock_retention_period)

                csm.module.setKeyRemovalCharge(0, from_=self.admin)

                for no in csm.node_operators.values():
                    for index in range(no.deposited_keys + no.withdrawn_keys):
                        if not no.withdrawn[index]:
                            self._withdraw(
                                no, index, update_state=False, full_withdraw=True
                            )

                    to_remove = (
                        no.total_keys_count - no.deposited_keys - no.withdrawn_keys
                    )
                    if to_remove > 0:
                        csm.module.removeKeys(
                            no.id,
                            no.deposited_keys + no.withdrawn_keys,
                            to_remove,
                            from_=no.manager,
                        )

                    assert csm.accounting.getBondShares(no.id) == no.bond_shares
                    assert (
                        csm.fee_distributor.distributedShares(no.id)
                        == no.claimed_rewards
                    )
                    assert csm.module.getNodeOperatorNonWithdrawnKeys(no.id) == 0
                    claimable_shares = (
                        no.bond_shares + no.total_rewards - no.claimed_rewards
                    )
                    with may_revert(CSAccounting.NothingToClaim):
                        if (
                            keccak256(abi.encode(uint(no.id), uint(no.total_rewards)))
                            in csm.rewards_tree._leaves
                        ):
                            proof = csm.rewards_tree.get_proof(
                                csm.rewards_tree._leaves.index(
                                    keccak256(
                                        abi.encode(uint(no.id), uint(no.total_rewards))
                                    )
                                )
                            )
                            if len(proof) == 0:
                                # cannot claim if the proof is empty, have to pull the rewards first
                                csm.accounting.pullFeeRewards(
                                    no.id,
                                    no.total_rewards,
                                    proof,
                                    from_=random_account(),
                                )
                        else:
                            proof = []

                        tx = csm.module.claimRewardsStETH(
                            no.id,
                            2**256 - 1,
                            no.total_rewards,
                            (
                                csm.rewards_tree.get_proof(
                                    csm.rewards_tree._leaves.index(
                                        keccak256(
                                            abi.encode(
                                                uint(no.id), uint(no.total_rewards)
                                            )
                                        )
                                    )
                                )
                                if keccak256(
                                    abi.encode(uint(no.id), uint(no.total_rewards))
                                )
                                in csm.rewards_tree._leaves
                                else []
                            ),
                            from_=no.manager,
                        )
                        e = [
                            e
                            for e in tx.raw_events
                            if isinstance(e, UnknownEvent)
                            and e.topics[0]
                            == bytes.fromhex(
                                "9d9c909296d9c674451c0c24f02cb64981eb3b727f99865939192f880a755dcb"
                            )
                        ][-1]
                        claimed_shares = abi.decode(e.data, [uint])
                        assert claimed_shares == claimable_shares

                assert csm.accounting.totalBondShares() == LIDO.sharesOf(csm.accounting)
                assert LIDO.sharesOf(csm.accounting) == 0

    @flow()
    def go_future(self):
        if random_bool():
            chain.mine(lambda x: random_int(15 * 60, 30 * 60) + x)


@chain.connect(fork="http://localhost:8545@20727896")
@on_revert(revert_handler)
def test_lido():
    LidoFuzzTest().run(3, 10000)
