// SPDX-License-Identifier: GPL-3.0

import { QueueLib, Batch } from "../../csm/src/lib/QueueLib.sol";
import { NodeOperator } from "../../csm/src/interfaces/ICSModule.sol";


contract MockQueue {
    using QueueLib for QueueLib.Queue;
    QueueLib.Queue public basicQueue;
    mapping(uint256 => NodeOperator) private nodeOperators;

    function addNodeOperator(
        uint256 numberOperatorId,
        uint32 keysCount
    ) external {
        nodeOperators[numberOperatorId].depositableValidatorsCount = keysCount;
        nodeOperators[numberOperatorId].enqueuedCount = 0;
    }

    function addKeysToNodeOperator(
        uint256 numberOperatorId,
        uint32 keysCount
    ) external {
        nodeOperators[numberOperatorId].depositableValidatorsCount += keysCount;
    }

    function removeKeysToNodeOperator(
        uint256 numberOperatorId,
        uint32 keysCount
    ) external {
        require(
            nodeOperators[numberOperatorId].depositableValidatorsCount >=
                keysCount,
            "Amount of keys to Remove is bigger than allocated keys"
        );
        nodeOperators[numberOperatorId].depositableValidatorsCount -= keysCount;
    }

    function normalizeQueue(uint256 nodeOperatorId) external {
        basicQueue.normalize(nodeOperators, nodeOperatorId);
    }

    function cleanQueue(uint256 maxItems) external returns (uint256, uint256) {
        return basicQueue.clean(nodeOperators, maxItems);
    }

    function at(uint128 index) external view returns (Batch) {
        // here we can check invariant on batches
        return basicQueue.queue[index];
    }

    function peek() external view returns (Batch) {
        return basicQueue.queue[basicQueue.head];
    }
}