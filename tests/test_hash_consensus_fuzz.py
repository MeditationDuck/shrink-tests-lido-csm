import logging
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
from pytypes.csm.src.interfaces.ICSModule import NodeOperator
from pytypes.csm.src.interfaces.IBurner import IBurner

from .merkle_tree import MerkleTree

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12
EPOCHS_PER_FRAME = 225 * 28  # 28 days
GENESIS_TIME = 1606824023
FAST_LANE_LENGTH_SLOTS = 0

CONSENSUS_VERSION = 1

def timestamp_to_slot(timestamp: uint) -> uint:
    return (timestamp - GENESIS_TIME) // SECONDS_PER_SLOT


def timestamp_to_epoch(timestamp: uint) -> uint:
    return timestamp_to_slot(timestamp) // SLOTS_PER_EPOCH

@dataclass
class ReportingState:
    last_report_ref_slot: uint
    last_consensus_ref_slot: uint
    last_consensus_report: uint

@dataclass
class MemberState:
    last_report_ref_slot: uint
    last_report_hash: bytes32

class HashConsensusFuzzTest(FuzzTest):
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
    initial_epoch: int
    consensus_quorum: int
    last_report_ref_slot: int
    rewards_tree: MerkleTree

    # IMPORTANT DATA
    consensus_members: Dict[Account,uint]
    consensus_members_data: Dict[Account, MemberState]
    reverted_consensus_members: List[Account]
    data_hashes: Dict[uint,Dict[bytes,uint]]
    manage_frame_config_role: List[Address]
    quorum_manager_role: List[Address]
    disable_quorum_manager_role: List[Address]
    fast_lane_config_role: List[Address]
    total_members: uint
    current_fast_lane_length: uint
    reporting_state: ReportingState

    def pre_sequence(self) -> None:
        # NEEDED CONFIGURATION

        NOAddresses.deploy()
        AssetRecovererLib.deploy()
        QueueLib.deploy()
        self.consensus_quorum = 0
        self.last_report_ref_slot = -1
        self.rewards_tree = MerkleTree()

        self.consensus_version = CONSENSUS_VERSION
        self.admin = random_account()

        self.fee_oracle = CSFeeOracle(OssifiableProxy.deploy(
            CSFeeOracle.deploy(
                SECONDS_PER_SLOT,
                GENESIS_TIME,
            ),
            self.admin,
            b"",
        ))

        self.hash_consensus = HashConsensus.deploy(
            SLOTS_PER_EPOCH,
            SECONDS_PER_SLOT,
            GENESIS_TIME,
            EPOCHS_PER_FRAME,
            FAST_LANE_LENGTH_SLOTS,
            self.admin,
            self.fee_oracle,
        )
        self.fee_oracle.initialize(
            self.admin,
            Address(1), # cannot set Address(0x0) as there is the check
            self.hash_consensus,
            self.consensus_version,
            0
        )

        self.hash_consensus.grantRole(self.hash_consensus.MANAGE_MEMBERS_AND_QUORUM_ROLE(), self.admin, from_=self.admin)
        self.initial_epoch = timestamp_to_epoch(chain.blocks["pending"].timestamp)
        self.hash_consensus.updateInitialEpoch(self.initial_epoch, from_=self.admin)


        # IMPORTANT TOWARDS HashConsensus.sol

        # FRAME CONFIG
        self.epoch_per_frame = EPOCHS_PER_FRAME
        frame_config_manager_1 = random_address()
        frame_config_manager_2 = random_address()
        self.manage_frame_config_role = []
        self.manage_frame_config_role.append(frame_config_manager_1)
        self.manage_frame_config_role.append(frame_config_manager_2)
        self.hash_consensus.grantRole(self.hash_consensus.MANAGE_FRAME_CONFIG_ROLE(),account=frame_config_manager_1,from_=self.admin)
        self.hash_consensus.grantRole(self.hash_consensus.MANAGE_FRAME_CONFIG_ROLE(),account=frame_config_manager_2,from_=self.admin)

        # QUORUM CONFIG
        quorum_manager_1 = random_address()
        quorum_manager_2 = random_address()
        self.quorum_manager_role = []
        self.quorum_manager_role.append(quorum_manager_1)
        self.quorum_manager_role.append(quorum_manager_2)
        self.hash_consensus.grantRole(self.hash_consensus.MANAGE_MEMBERS_AND_QUORUM_ROLE(),account=quorum_manager_1, from_=self.admin)
        self.hash_consensus.grantRole(self.hash_consensus.MANAGE_MEMBERS_AND_QUORUM_ROLE(),account=quorum_manager_2, from_=self.admin)

        disable_quorum_manager_1 = random_address()
        disable_quorum_manager_2 = random_address()
        self.disable_quorum_manager_role = []
        self.disable_quorum_manager_role.append(disable_quorum_manager_1)
        self.disable_quorum_manager_role.append(disable_quorum_manager_2)
        self.hash_consensus.grantRole(self.hash_consensus.DISABLE_CONSENSUS_ROLE(), account=disable_quorum_manager_1, from_=self.admin)
        self.hash_consensus.grantRole(self.hash_consensus.DISABLE_CONSENSUS_ROLE(), account=disable_quorum_manager_2, from_=self.admin)

        # FASTLANE CONFIG
        fast_lane_manager_1 = random_address()
        fast_lane_manager_2 = random_address()
        self.fast_lane_config_role = []
        self.fast_lane_config_role.append(fast_lane_manager_1)
        self.fast_lane_config_role.append(fast_lane_manager_2)
        self.hash_consensus.grantRole(self.hash_consensus.MANAGE_FAST_LANE_CONFIG_ROLE(), account=fast_lane_manager_1, from_=self.admin)
        self.hash_consensus.grantRole(self.hash_consensus.MANAGE_FAST_LANE_CONFIG_ROLE(), account=fast_lane_manager_2, from_=self.admin)

        self.reverted_consensus_members = []
        self.consensus_members = {}
        self.data_hashes = {}
        self.total_members = 0
        self.current_fast_lane_length = 0

        # REPORTS CONFIG
        self.reporting_state = ReportingState(0,0,0)
        self.consensus_members_data = {}

        
    def post_invariants(self) -> None:
        if random_bool():
            time_delta = random_int(60 * 60, 24 * 60 * 60)
            chain.mine(lambda t: t + time_delta)

    def _get_frame_info(self, timestamp: uint) -> Tuple[uint, uint]:
        epoch = timestamp_to_epoch(timestamp)
        frame_start_epoch = (epoch - self.initial_epoch) // self.epoch_per_frame * self.epoch_per_frame + self.initial_epoch
        frame_start_slot = frame_start_epoch * SLOTS_PER_EPOCH
        next_frame_start_slot = (frame_start_epoch + self.epoch_per_frame) * SLOTS_PER_EPOCH
        return frame_start_slot - 1, next_frame_start_slot - 1
    
    def _show_data_hashes(self):
        logger.info("ALL REPORTS:")
    
        for ref_slot, reports in self.data_hashes.items():
                logger.warning(f"the ref_slot {ref_slot}: ")

                for hash, votes in reports.items():
                    additional_phrase = ""
                    if votes >= self.consensus_quorum:
                        additional_phrase = " -- READY TO BE PROCESSED"

                    logger.warning(f"\t {hash}: {votes} {additional_phrase}")
    
    def _get_slot_at_timestamp(self,timestamp):
        return (timestamp - GENESIS_TIME) // SECONDS_PER_SLOT
    
    def _get_epoch_at_slot(self, timestamp: uint):
        slot_at_timestamp = (timestamp - GENESIS_TIME) // SECONDS_PER_SLOT
        epoch_at_slot = slot_at_timestamp // SLOTS_PER_EPOCH 
        return epoch_at_slot


    def _get_fast_lane_subset(self, timestamp: uint) -> Tuple[uint, uint]:
        if self.consensus_quorum < len(list(self.reverted_consensus_members)):
            slot_at_timestamp = self._get_slot_at_timestamp(timestamp)
            epoch_at_slot = slot_at_timestamp // SLOTS_PER_EPOCH
            frame_index = (epoch_at_slot - self.initial_epoch) // self.epoch_per_frame
            start_index = frame_index % len(list(self.reverted_consensus_members))
            past_end_index = start_index + self.consensus_quorum 
            return (start_index, past_end_index)
        else:
            return (0, len(list(self.reverted_consensus_members)))
    

    def _is_sender_in_fast_lane(self,member_index, start_index, end_index, total_members):
        return ((member_index + total_members - start_index) % total_members) <= ((end_index - start_index) % total_members)


    @flow(weight=500)
    def flow_set_frame_config(self):
        frame_config_role = random.choice(self.manage_frame_config_role)
        epoch_per_frame = random_int(min=int(EPOCHS_PER_FRAME/2),max=EPOCHS_PER_FRAME*2)

        current_epoch_at_timestamp = self._get_epoch_at_slot(chain.blocks["pending"].timestamp)
        current_frame_index = (current_epoch_at_timestamp - self.initial_epoch) // self.epoch_per_frame
        current_start_epoch_of_frame_with_index = self.initial_epoch + current_frame_index * self.epoch_per_frame

        self.initial_epoch = current_start_epoch_of_frame_with_index
        self.epoch_per_frame = epoch_per_frame
        
        fast_lane_length = 0
        if random_bool():
            fast_lane_length = random_int(0,self.epoch_per_frame * SLOTS_PER_EPOCH)
            
        self.hash_consensus.setFrameConfig(epochsPerFrame=epoch_per_frame, fastLaneLengthSlots=fast_lane_length, from_=frame_config_role)
        self.current_fast_lane_length = fast_lane_length
        (setted_initial_epoch, setted_epoch_per_frame, fastLaneLengthSlot) = self.hash_consensus.getFrameConfig()
        assert(self.initial_epoch == setted_initial_epoch)
        assert(self.epoch_per_frame == setted_epoch_per_frame)
        assert(self.current_fast_lane_length == fastLaneLengthSlot)

        logger.info(f"Config is changed: epoch_per_frame: {epoch_per_frame}")


    @flow(weight=300)
    def flow_set_quorum(self):
        if len(list(self.reverted_consensus_members)) == 0: return
        too_small_number = random_bool()
        if too_small_number:
            new_quorum = random_int(0,int(len(list(self.reverted_consensus_members))/2))
            with must_revert(self.hash_consensus.QuorumTooSmall) as e:
                self.hash_consensus.setQuorum(new_quorum)
            if e is not None:
                logger.info("setQuorum: too small number for consensus")
        else:
            new_quorum = random_int(int(len(list(self.reverted_consensus_members))//2)+1,len(list(self.reverted_consensus_members)))
            self.hash_consensus.setQuorum(new_quorum, from_=random.choice(self.quorum_manager_role))
            self.consensus_quorum  = new_quorum
            

    @flow(weight=100)
    def flow_disable_quorum(self):
        unauthorized = random_bool()
        if unauthorized:
            sender = random_address()
        else:
            sender = random.choice(self.disable_quorum_manager_role)

        if unauthorized and self.consensus_quorum != 2**256 - 1:
            with must_revert(self.hash_consensus.AccessControlUnauthorizedAccount(sender,self.hash_consensus.DISABLE_CONSENSUS_ROLE())):
                self.hash_consensus.disableConsensus(from_=sender)
        else:
            self.hash_consensus.disableConsensus(from_=sender)
            self.consensus_quorum = 2**256 - 1
            logger.info("Quorum has been disabled")
    

    @flow(weight=400)
    def flow_set_fast_lane(self):
        
        sender = random.choice(self.fast_lane_config_role)
        if random_bool():
            fast_lane_length = random_int(0,self.epoch_per_frame * SLOTS_PER_EPOCH)
            self.hash_consensus.setFastLaneLengthSlots(fast_lane_length, from_=sender)
            logger.info(f"Changed fastLaneLength to: {fast_lane_length}")
            self.current_fast_lane_length = fast_lane_length
        else:
            fast_lane_length = random_int(self.epoch_per_frame * SLOTS_PER_EPOCH + 1, self.epoch_per_frame * SLOTS_PER_EPOCH * 10)
            with must_revert(self.hash_consensus.FastLanePeriodCannotBeLongerThanFrame):
                self.hash_consensus.setFastLaneLengthSlots(fast_lane_length, from_=sender)
            logger.info(f"NOT Changed fastLaneLength to: {fast_lane_length}")


    @flow(weight=1000)
    def flow_add_consensus_member(self):
        member = random_account()
        quorum = (len(list(self.reverted_consensus_members)) + 1) // 2 + 1
        with may_revert(HashConsensus.DuplicateMember) as e:
            self.hash_consensus.addMember(member, quorum, from_=self.admin)

        if member in list(self.reverted_consensus_members):
            assert e.value is not None
        else:
            assert e.value is None
            self.consensus_members[member] = self.total_members
            self.reverted_consensus_members.append(member)
            self.total_members += 1
            self.consensus_quorum = quorum
            self.consensus_members_data[member] = MemberState(0,0)
            logger.info(f"Added consensus member {member} (index: {self.consensus_members[member]}) with quorum {quorum}")
            assert len(self.consensus_members) == len(self.reverted_consensus_members), "Inconsistency detected after addition!"


    @flow(weight=500)
    def flow_remove_consensus_member(self):
        member = random_account()
        quorum = (len(list(self.reverted_consensus_members)) - 1) // 2 + 1

        with may_revert(HashConsensus.NonMember) as e:
            self.hash_consensus.removeMember(member, quorum, from_=self.admin)

        if member in list(self.reverted_consensus_members):
            logger.info(f"DELETING THE MEMBER: {member}")
            assert e.value is None
            removed_member_index = self.consensus_members[member]
            address_to_assign_removed_index = self.reverted_consensus_members[self.total_members-1] 

            self.consensus_members[address_to_assign_removed_index] = removed_member_index
            del self.consensus_members[member] 

            self.reverted_consensus_members[removed_member_index] = address_to_assign_removed_index
            self.reverted_consensus_members.pop()  

            self.total_members -= 1
            self.consensus_quorum = quorum
            logger.info(f"Removed consensus member {member} (index: {removed_member_index}) with quorum {quorum}")

            # deleting this member vote in current ref_slot
            ref_slot = self._get_frame_info(chain.blocks["pending"].timestamp)[0]
            if ref_slot == self.consensus_members_data[member].last_report_ref_slot:
                self.data_hashes[ref_slot][self.consensus_members_data[member].last_report_hash] -= 1 

            assert len(self.consensus_members) == len(self.reverted_consensus_members), "Inconsistency detected after removal!"
        else:
            assert e.value is not None


    @flow(weight=500)
    def flow_submit_new_hash(self):
        if (len(self.reverted_consensus_members) == 0): return 

        # generating/getting data for inputs
        ref_slot = self._get_frame_info(chain.blocks["pending"].timestamp)[0]
        sender = random.choice(list(self.reverted_consensus_members))
        new_data_hash = bytes(random_bytes(32))
        (start_index, end_index) = self._get_fast_lane_subset(chain.blocks["pending"].timestamp)
        sender_in_fast_lane = self._is_sender_in_fast_lane(self.consensus_members[sender], start_index, end_index-1, len(list(self.reverted_consensus_members)))
        current_slot = self._get_slot_at_timestamp(chain.blocks["pending"].timestamp) 
        fast_lane_length_slots = self.current_fast_lane_length

        # change the state of the current voting period
        if (self.reporting_state.last_report_ref_slot != ref_slot):
            self.reporting_state.last_report_ref_slot = ref_slot

        if (sender_in_fast_lane or (current_slot >= ref_slot + fast_lane_length_slots) ):
            logger.info(f"NEW hash is submitted for ref_slot: {ref_slot}; hash: {new_data_hash}; address of sender: {sender}")
            # HashConsensus.DuplicateReport should never occur because of the consensus report
            tx = self.hash_consensus.submitReport(ref_slot, new_data_hash, self.consensus_version, from_=sender) 

            self.data_hashes.setdefault(ref_slot,{})[new_data_hash] = 1
            if self.consensus_members_data[sender].last_report_ref_slot == ref_slot:
                self.data_hashes[ref_slot][self.consensus_members_data[sender].last_report_hash] -= 1

                if self.data_hashes[ref_slot][self.consensus_members_data[sender].last_report_hash] == self.consensus_quorum - 1:
                    consensus_lost = False
                    for index, event in enumerate(tx.raw_events):
                        if len(event.topics) == 0:
                            continue
                        if event.topics[0] == HashConsensus.ConsensusLost.selector:
                            logger.info(f"Consensus LOST for {self.consensus_members_data[sender].last_report_hash}! needed quorum: {self.consensus_quorum}")
                            consensus_lost = True
                    if consensus_lost == False:
                        raise Exception("Consensus IS NOT lost when expected!")
                    self.reporting_state.last_consensus_ref_slot = 0            

            self.consensus_members_data[sender].last_report_hash = new_data_hash
            self.consensus_members_data[sender].last_report_ref_slot = ref_slot            

        else:
            with must_revert(HashConsensus.NonFastLaneMemberCannotReportWithinFastLaneInterval) as e:
                self.hash_consensus.submitReport(ref_slot, new_data_hash, self.consensus_version, from_=sender)


    @flow(weight=100)
    def flow_submit_to_invalid_slot(self):
        if (len(list(self.reverted_consensus_members)) == 0): return 
        current_frame_data = self._get_frame_info(chain.blocks["pending"].timestamp)

        ref_slot_to_vote = current_frame_data[0]        
        next_ref_slot_to_vote = current_frame_data[1]

        choice_to_check = random.choice(["previous_ref_slot","next_ref_slot", "random_slot"])
        if choice_to_check == "previous_ref_slot":
            invalid_ref_slot = ref_slot_to_vote - (225*28*32)
        elif choice_to_check == "next_ref_slot":
            invalid_ref_slot = ref_slot_to_vote + (225*28*32)
        else:
            invalid_ref_slot = random_int(ref_slot_to_vote+1,next_ref_slot_to_vote-1)

        sender = random.choice(list(self.reverted_consensus_members))
        new_data_hash = bytes(random_bytes(32))

        with must_revert(HashConsensus.InvalidSlot):
            self.hash_consensus.submitReport(invalid_ref_slot, new_data_hash, self.consensus_version, from_=sender)
        logger.info(f"Invalid slot. Reason: {choice_to_check}")
        

    @flow(weight=50)
    def flow_submit_hash_invalid_consensus_version(self):
        if (len(list(self.reverted_consensus_members)) == 0): return 
        current_frame_data = self._get_frame_info(chain.blocks["pending"].timestamp)

        ref_slot_to_vote = current_frame_data[0]        
        sender = random.choice(list(self.reverted_consensus_members))

        random_version = random_int(4,30)
        while random_version == self.consensus_version:
            random_version = random_int(4,30)

        new_data_hash = bytes(random_bytes(32))
        with must_revert(HashConsensus.UnexpectedConsensusVersion):
            self.hash_consensus.submitReport(ref_slot_to_vote, new_data_hash, random_version, from_=sender)
        logger.info(f"Sent report with invalid version: {random_version}" )


    @flow(weight=500)
    def flow_submit_hash_by_invalid_user(self):
        current_frame_data = self._get_frame_info(chain.blocks["pending"].timestamp)

        ref_slot_to_vote = current_frame_data[0]        
        sender = random_address()

        new_data_hash = bytes(random_bytes(32))
        with must_revert(HashConsensus.NonMember):
            self.hash_consensus.submitReport(ref_slot_to_vote, new_data_hash, self.consensus_version, from_=sender)
        logger.info(f"Sent report by NOT MEMBER" )


    @flow(weight=5000)
    def flow_submit_existing_hash(self):
        if (len(self.reverted_consensus_members) == 0): return 
        ref_slot = self._get_frame_info(chain.blocks["pending"].timestamp)[0]
        if not self.data_hashes.get(ref_slot): return

        sender = random.choice(list(self.reverted_consensus_members))
        existing_data_hash = random.choice(list(self.data_hashes[ref_slot].keys()))

        (start_index, end_index) = self._get_fast_lane_subset(chain.blocks["pending"].timestamp)
        sender_in_fast_lane = self._is_sender_in_fast_lane(self.consensus_members[sender], start_index, end_index - 1, len(list(self.reverted_consensus_members)))
        current_slot = self._get_slot_at_timestamp(chain.blocks["pending"].timestamp) 

        fast_lane_length_slots = self.current_fast_lane_length

        if sender_in_fast_lane or (current_slot >= ref_slot + fast_lane_length_slots):
            logger.info(f"EXISTING hash is submitted for ref_slot: {ref_slot}; hash: {existing_data_hash}; address of sender: {sender}")
            with may_revert(HashConsensus.DuplicateReport) as e:
                tx: TransactionAbc = self.hash_consensus.submitReport(ref_slot, existing_data_hash, self.consensus_version, from_=sender)
            if e.value is None:
                # check if this report is not duplicate nor to another slot
                self.data_hashes[ref_slot][existing_data_hash] += 1

                if self.consensus_members_data[sender].last_report_ref_slot == ref_slot:
                    self.data_hashes[ref_slot][self.consensus_members_data[sender].last_report_hash] -= 1
                # check if the consensus has been reached
                if self.data_hashes[ref_slot][existing_data_hash] == self.consensus_quorum:
                    consensus_reached = False
                    for index, event in enumerate(tx.raw_events):
                        if len(event.topics) == 0:
                            continue
                        if event.topics[0] == HashConsensus.ConsensusReached.selector:
                            logger.info(f"Consensus reached for {existing_data_hash}! needed quorum: {self.consensus_quorum}")
                            consensus_reached = True

                            if self.reporting_state.last_consensus_ref_slot != ref_slot or \
                                self.reporting_state.last_consensus_report != existing_data_hash:
                                self.reporting_state.last_consensus_ref_slot = ref_slot
                                self.reporting_state.last_consensus_report = existing_data_hash
                    if consensus_reached == False:
                        raise Exception("Consensus IS NOT reached when expected!")
                    self.reporting_state.last_consensus_ref_slot = ref_slot
                    self.reporting_state.last_consensus_report = existing_data_hash
                # check if the consensus has been discarded:
                elif self.consensus_members_data[sender].last_report_hash != 0 and  \
                    self.consensus_members_data[sender].last_report_ref_slot == ref_slot and \
                    self.data_hashes[ref_slot][self.consensus_members_data[sender].last_report_hash] == self.consensus_quorum - 1:
                    consensus_discarded = False
                    for index, event in enumerate(tx.raw_events):
                        if len(event.topics) == 0:
                            continue
                        if event.topics[0] == HashConsensus.ConsensusLost.selector:
                            logger.info(f"Consensus lost for {self.consensus_members_data[sender].last_report_hash}! Needed quorum: {self.consensus_quorum}")
                            consensus_discarded = True

                            if self.reporting_state.last_consensus_ref_slot != ref_slot:
                                self.reporting_state.last_consensus_ref_slot = 0
                    if consensus_discarded == False:
                        raise Exception("Consensus IS NOT lost when expected!")
                        
                self.consensus_members_data[sender].last_report_hash = existing_data_hash
                self.consensus_members_data[sender].last_report_ref_slot = ref_slot 
        else:
            with must_revert(HashConsensus.NonFastLaneMemberCannotReportWithinFastLaneInterval) as e:
                tx = self.hash_consensus.submitReport(ref_slot, existing_data_hash, self.consensus_version, from_=sender)
                    

    @invariant()
    def invariant_frame_config(self):
        (initialEpoch, epoch_per_frame, fast_lane_length_slots) = self.hash_consensus.getFrameConfig()
        assert self.initial_epoch == initialEpoch
        assert self.epoch_per_frame == epoch_per_frame 
        assert self.current_fast_lane_length == fast_lane_length_slots
    
    @invariant()
    def invariant_get_current_frame(self):
        (ref_slot_solidity, report_processing_deadline_solidity) = self.hash_consensus.getCurrentFrame()
        ref_slot_python = self._get_frame_info(chain.blocks["pending"].timestamp)[0]
        report_processing_deadline_python = self._get_frame_info(chain.blocks["pending"].timestamp)[1]
        assert ref_slot_solidity == ref_slot_python
        assert report_processing_deadline_python == report_processing_deadline_solidity

    @invariant()
    def invariant_get_initial_ref_slot(self):
        initial_ref_slot_solidity = self.hash_consensus.getInitialRefSlot()
        frame_start_epoch = self.initial_epoch + 0 * self.epoch_per_frame
        frame_start_slot = frame_start_epoch * SLOTS_PER_EPOCH
        assert (frame_start_slot - 1) == initial_ref_slot_solidity

 
    @invariant()
    def invariant_compare_reports(self):
        reports_solidity, votes_solidity = self.hash_consensus.getReportVariants()
        ref_slot_solidity, deadline = self.hash_consensus.getCurrentFrame()
        ref_slot_python = self._get_frame_info(chain.blocks["pending"].timestamp)[0]

        assert ref_slot_python == ref_slot_solidity

        try: 
            reports_python = self.data_hashes[ref_slot_python]
        except:
            # There are no reports for current ref_slot
            return

        for report, vote in zip(reports_solidity,votes_solidity):
            if reports_python[report] != vote:
                logger.critical(f"{reports_python[report]} != {vote}")


@chain.connect(fork="http://localhost:8545", accounts=20)
def test_csm():
    HashConsensusFuzzTest().run(10, 10_000)


