import logging
from typing import Dict, Tuple
from pytypes.csm.src.lib.QueueLib import IQueueLib
from pytypes.tests.helpers.MockQueue import MockQueue
from pytypes.csm.src.lib.QueueLib import QueueLib
from wake.testing import *
from wake.testing.fuzzing import *
from dataclasses import dataclass


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

@dataclass
class Batch:
    noId: uint
    keys: uint
    next: uint

@dataclass
class NodeOperator:
    depositable_validators_count: uint
    enqueued_count: uint

class QueueFeatured:
    _head: uint
    _tail: uint
    batch_queue: List[Batch]

    def __init__(self):
        self._head = 0
        self._tail = 0
        self.batch_queue = []

    def __getitem__(self, index: int) -> Batch:
        if len(self.batch_queue) <= index:
            return Batch(0,0,0)
        return self.batch_queue[index]

    def __len__(self) -> int:
        return len(self.batch_queue)

    @property
    def head(self) -> int:
        return self._head

    @head.setter
    def head(self, value):
        self._head = value

    @property
    def tail(self) -> int:
        return self._tail

    @tail.setter
    def tail(self, value) -> int:
        self._tail = value

    def clean_queue(self, node_operators: List[NodeOperator], max_count: int) -> Tuple[int, int]:
        curr: Batch = self[self.head]
        curr_index = self.head
        prev: Batch = None
        prev_index: uint = -1

        local_calculation_of_keys: Dict[int, int] = {}
        to_delete = 0
        last_removal_pos = 0

        for i in range(max_count):
            if (curr == Batch(0,0,0)):
                return (to_delete, last_removal_pos)
            local_calculation_of_keys.setdefault(curr.noId,0)
            if (local_calculation_of_keys[curr.noId] >= node_operators[curr.noId].depositable_validators_count):
                if curr_index == self.head:
                    self.head = self.batch_queue[self.head].next
                    logger.info(f"Deleted first element from the queue. current head: {self.head}")
                else:
                    self.batch_queue[prev_index].next = self.batch_queue[curr_index].next
                    next_element_index = self.batch_queue[curr_index].next
                    logger.info(f"Rebind elements: {prev_index} - {curr_index} - {next_element_index} in the queue")
                    logger.info(f"{prev_index}: noId-{self[prev_index].noId} keys-{self[prev_index].keys} next-{self[prev_index].next}")
                    logger.info(f"{curr_index}: noId-{self[curr_index].noId} keys-{self[curr_index].keys} next-{self[curr_index].next}")
                    logger.info(f"{next_element_index}: noId-{self[next_element_index].noId} keys-{self[next_element_index].keys} next-{self[next_element_index].next}")

                node_operators[curr.noId].enqueued_count -= curr.keys
                to_delete += 1
                last_removal_pos = i + 1
            else:
                prev_index = curr_index

            local_calculation_of_keys[curr.noId] = local_calculation_of_keys.setdefault(curr.noId, 0) + curr.keys

            curr_index = curr.next
            if curr_index != self.tail:
                curr = self.batch_queue[curr.next]
            else:
                break
        return (to_delete, last_removal_pos)

    def normalize_queue(self, node_opearotrs: List[NodeOperator], node_operator_id: int) -> int:
        enqueue_amount = node_opearotrs[node_operator_id].depositable_validators_count - node_opearotrs[node_operator_id].enqueued_count
        if len(self) - 1 >= 0 and self[len(self)-1] == Batch(0,0,0):
             self.batch_queue[len(self)-1] = Batch(noId=node_operator_id, keys=enqueue_amount, next=self.tail+1)
        else:
            self.batch_queue.append(Batch(noId=node_operator_id, keys=enqueue_amount, next=self.tail+1))

        if self.head == -1:
            self.head = 0
            self.tail = 1
        else:
            self.tail += 1
        return enqueue_amount


class QueueFuzzTest(FuzzTest):
    mainQueue: MockQueue
    simulated_queue: QueueFeatured
    node_operators: List[NodeOperator]
    count_of_elemenets_in_queue: uint

    def pre_sequence(self) -> None:
        QueueLib.deploy()
        self.mainQueue = MockQueue.deploy()
        self.node_operators = []
        self.count_of_elemenets_in_queue = 0
        self.simulated_queue = QueueFeatured()
        self.flow_add_node_operator()

    @flow(weight=50)
    def flow_add_node_operator(self):
        number_operator_id = len(self.node_operators)
        keys_count = random_int(1, 25)
        self.mainQueue.addNodeOperator(number_operator_id, keys_count)
        self.node_operators.append(NodeOperator(0,0))
        self.node_operators[number_operator_id].depositable_validators_count = keys_count
        self.node_operators[number_operator_id].enqueued_count = 0
        logger.info(f"Added {number_operator_id} NO with {keys_count} keys")

    @flow(weight=500)
    def flow_add_keys_to_node_operator(self):
        number_operator_id = random_int(0,len(self.node_operators)-1)
        keys_count = random_int(1, 25)
        self.mainQueue.addKeysToNodeOperator(number_operator_id, keys_count)
        self.node_operators[number_operator_id].depositable_validators_count += keys_count
        logger.info(f"Added to {number_operator_id} NO ADDITIONAL with {keys_count} keys")

    @flow(weight=300)
    def flow_remove_keys_to_node_operator(self):
        number_operator_id = random_int(0,len(self.node_operators)-1)
        keys_count = random_int(0, self.node_operators[number_operator_id].depositable_validators_count)
        self.mainQueue.removeKeysToNodeOperator(number_operator_id, keys_count)
        self.node_operators[number_operator_id].depositable_validators_count -= keys_count
        logger.info(f"Removed from {number_operator_id} NO {keys_count} keys")

    @flow(weight=450)
    def flow_normalize_node_operator(self):
        random_no = random_int(0,len(self.node_operators)-1)

        tx = self.mainQueue.normalizeQueue(nodeOperatorId=random_no)
        normalization_happen = False
        enqueue_amount = 0
        for index, event in enumerate(tx.raw_events):
            if len(event.topics) == 0:
                continue
            if event.topics[0] == IQueueLib.BatchEnqueued.selector:
                (keys,) = Abi.decode(["uint256"], event.data)

                enqueue_amount = self.simulated_queue.normalize_queue(node_opearotrs=self.node_operators, node_operator_id=random_no)
                logger.info(f"Batch from {random_no} NO with {enqueue_amount} has been added to the queue! Index in a queue: {self.simulated_queue.tail - 1}")
                self.node_operators[random_no].enqueued_count += enqueue_amount
                assert enqueue_amount == keys
                normalization_happen = True

        if enqueue_amount <= 0:
            if normalization_happen:
                raise Exception("Normalization applied, when hasn't to be")
        else:
            if not normalization_happen:
                raise Exception("Normalization NOT applied, when has to be")

    @flow(weight=300)
    def flow_clean_node_operators(self):
        if len(self.simulated_queue) == 0:
            return

        max_items_to_analyze = random_int(1,len(self.simulated_queue.batch_queue))
        tx = self.mainQueue.cleanQueue(max_items_to_analyze)

        to_delete = self.simulated_queue.clean_queue(self.node_operators, max_items_to_analyze)
        assert to_delete == tx.return_value

    def extract_fields(self,batch_uint: uint):
        node_operator_id = batch_uint >> 192
        keys_count = (batch_uint >> 128) & ((1 << 64) - 1)
        next = batch_uint & ((1 << 128) - 1)

        return Batch(node_operator_id, keys_count, next)

    @invariant()
    def invariant_compare_queues(self):
        length_of_the_queue = len(self.simulated_queue)
        for i in range (length_of_the_queue):
            batch_uint = self.mainQueue.at(i)
            batch_structure = self.extract_fields(batch_uint)
            assert self.simulated_queue[i] == batch_structure


@default_chain.connect(accounts=20)
def test_csm():
    QueueFuzzTest().run(1000, 100000)

