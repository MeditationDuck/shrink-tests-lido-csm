import bisect
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from itertools import count
import logging
from typing import ClassVar

from wake.testing import *
from wake.testing.fuzzing import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@dataclass
class Frame:
    """A frame represents a period of time in the Beacon Chain.

    Attributes:
        index (int): The index of the frame.
        first_epoch (int): The first epoch in the frame.
        last_epoch (int): The last epoch in the frame.
        first_slot (int): The first slot in the frame.
        last_slot (int): The last slot in the frame.
        reference_slot (int): The slot before the first slot in the frame.
        deadline (int): The last second of the frame.
    """
    index: int
    first_epoch: int
    last_epoch: int
    first_slot: int
    last_slot: int
    reference_slot: int
    deadline: int

class BeaconChain:
    """
    Represents a simulated Beacon Chain for testing purposes.

    Attributes:
        GENESIS_TIME (int): The timestamp of the genesis block.
        SECONDS_PER_SLOT (int): The number of seconds in each slot.
        SLOTS_PER_EPOCH (int): The number of slots in each epoch.
        EPOCHS_PER_FRAME (int): The number of epochs in each frame.
        INITIAL_EPOCH (int): The starting epoch for the simulation.
        chain (Chain): The associated blockchain instance.
    """
    def __init__(
        self,
        chain: Chain,
        *,
        genesis_time: int = 1606824023,
        seconds_per_slot: int = 12,
        slots_per_epoch: int = 32,
        epochs_per_frame: int = 225,
        initial_epoch: int = 0,
    ):
        self.GENESIS_TIME: int = genesis_time
        self.SECONDS_PER_SLOT: int = seconds_per_slot
        self.SLOTS_PER_EPOCH: int = slots_per_epoch
        self.EPOCHS_PER_FRAME: int = epochs_per_frame
        self.INITIAL_EPOCH: int = initial_epoch
        self.chain: Chain = chain
        # for quick access to the list indices by status
        self.skip_to_first_slot_of_next_frame()


    ############################################################
    # Chain state
    ############################################################

    @property
    def timestamp(self) -> int:
        """Return the timestamp of the next block to be mined.

        Returns:
            int: The timestamp of the next block.
        """
        return self.chain.blocks["latest"].timestamp

    @property
    def current_slot(self) -> int:
        """Return the slot number of the block to be mined next.

        Returns:
            int: The slot number of the next block.
        """
        return self._slot_at_timestamp(self.timestamp)

    @property
    def current_epoch(self) -> int:
        """Return the epoch number of the slot of the next block to be mined.

        Returns:
            int: The epoch number of the next block.
        """
        return self._epoch_at_slot(self.current_slot)

    @property
    def current_frame_index(self) -> int:
        """Return the index of the frame that the epoch of the next block belongs to.

        Returns:
            int: The index of the frame.
        """
        return self._frame_index_at_epoch(self.current_epoch)

    @property
    def current_frame(self) -> Frame:
        """Return the frame that the epoch of the next block belongs to.

        Returns:
            Frame: The current frame.
        """
        frame_index = self.current_frame_index
        return self.get_frame_at_index(frame_index)

    def get_frame_at_index(self, index: int) -> Frame:
        """Return the frame at the specified index.

        Args:
            index (int): The index of the frame to retrieve.

        Returns:
            Frame: The frame at the specified index.
        """
        frame_first_epoch = self.INITIAL_EPOCH + index * self.EPOCHS_PER_FRAME
        frame_last_epoch = frame_first_epoch + self.EPOCHS_PER_FRAME - 1
        frame_first_slot = frame_first_epoch * self.SLOTS_PER_EPOCH
        frame_last_slot = frame_first_slot + self.SLOTS_PER_EPOCH * self.EPOCHS_PER_FRAME - 1
        frame_reference_slot = frame_first_slot - 1
        frame_deadline = self._timestamp_at_slot(frame_last_slot + 1) - 1

        return Frame(
            index=index,
            first_epoch=frame_first_epoch,
            last_epoch=frame_last_epoch,
            first_slot=frame_first_slot,
            last_slot=frame_last_slot,
            reference_slot=frame_reference_slot,
            deadline=frame_deadline,
        )

    def _slot_at_timestamp(self, timestamp: int) -> int:
        """Return the slot number for the given timestamp.

        Args:
            timestamp (int): The timestamp to convert to a slot number.

        Returns:
            int: The slot number for the timestamp.
        """
        return (timestamp - self.GENESIS_TIME) // self.SECONDS_PER_SLOT

    def _timestamp_at_slot(self, slot: int) -> int:
        """Return the timestamp for the given slot.

        Args:
            slot (int): The slot number to convert to a timestamp.

        Returns:
            int: The timestamp for the slot.
        """
        return self.GENESIS_TIME + slot * self.SECONDS_PER_SLOT

    def _epoch_at_slot(self, slot: int) -> int:
        """Return the epoch number for the given slot.

        Args:
            slot (int): The slot number to convert to an epoch number.

        Returns:
            int: The epoch number for the slot.
        """
        return slot // self.SLOTS_PER_EPOCH

    def _frame_index_at_epoch(self, epoch: int) -> int:
        """Return the index of the frame that the epoch belongs to.

        Args:
            epoch (int): The epoch number to convert to a frame index.

        Returns:
            int: The index of the frame.
        """
        return (epoch - self.INITIAL_EPOCH) // self.EPOCHS_PER_FRAME

    ############################################################
    # Slot manipulation
    ############################################################

    def _next_slot(self) -> None:
        """Advance the chain state to the next slot."""
        self.chain.mine(lambda t: t + self.SECONDS_PER_SLOT)

    def skip_to_first_slot_of_next_frame(self) -> None:
        """Skip to the first slot of the next frame."""
        first_slot_of_next_frame = self.current_frame.last_slot + 1
        while self.current_slot < first_slot_of_next_frame:
            self._next_slot()
