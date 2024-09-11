import time
from wake.testing import *
from wake.testing.fuzzing import *
from pytypes.tests.helpers.MockGIndex import MockGIndex
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class IndexesOverflow(Exception):
    pass

class ValueOverflow(Exception):
    pass

class G_Index_Simulation():
    gI: uint256
    p: uint8
    value: bytes

    def __init__(self,value):
        self.gI = value >> 8
        self.p = 0xFF & value
        self.value = value

    def pack(self, gI: uint256, p: uint8) -> bytes:
        if (gI > 2**248-1):
            raise ValueOverflow
        self.gI = gI
        self.p = p
        self.value = ((self.gI << 8) | self.p).to_bytes(32, byteorder='big')
        return self.value
    
    def index(self) -> bytes:
        return self.gI
    
    def width(self):
        return 2**self.p
    
    def shift_right(self, n: uint):
        return ((( self.index()  + n) << 8) | self.p).to_bytes(32,byteorder='big')  
    
    def shift_left(self, n: uint):
        return ((self.index() - n) << 8 | self.p).to_bytes(32,byteorder='big')  

class GIndexFuzz(FuzzTest):
    mock_g_index: MockGIndex

    # concatenation
    first_mock_g_index: MockGIndex
    second_mock_g_index: MockGIndex

    simulated_g_index: G_Index_Simulation

    # concatenation
    first_simulated_g_index: G_Index_Simulation
    second_simulated_g_index: G_Index_Simulation

    @staticmethod
    def most_significant_bit_index(x: uint) -> int:
        return 256 if x == 0 else x.bit_length() - 1

    def pre_sequence(self):
        self.mock_g_index = MockGIndex.deploy()
        self.first_mock_g_index = MockGIndex.deploy()
        self.second_mock_g_index = MockGIndex.deploy()
        self.simulated_g_index = G_Index_Simulation(0x0)
        self.first_simulated_g_index = G_Index_Simulation(0x0)
        self.second_simulated_g_index = G_Index_Simulation(0x0)
        self.flow_pack()

    def concat_gindices(self, g_index_1: G_Index_Simulation, g_index_2: G_Index_Simulation) -> bytes:
        out = 1
        fls_g_index_1 = self.most_significant_bit_index(g_index_1.index())
        fls_g_index_2 = self.most_significant_bit_index(g_index_2.index())
        if (fls_g_index_1 + fls_g_index_2 + 1 > 248):
            raise IndexesOverflow()

        # 1 step
        out <<= fls_g_index_1
        out |=  g_index_1.index() ^ (1 << fls_g_index_1)

        # 2 step
        out <<= fls_g_index_2
        out |= g_index_2.index() ^ (1 << fls_g_index_2)

        if out > (2**248) - 1:
            raise ValueOverflow()

        return G_Index_Simulation(0x0).pack(out, g_index_2.p)

    @flow(weight=500)
    def flow_pack(self):

        gIndex = random_int(0, 2**248 - 1)
        p = random_int(0, 2**8-1)

        # this loop guarantees that generated GIndex will be valid
        while (gIndex < 2**p):
            gIndex = random_int(0, 2**248 - 1)
            p = random_int(0, 2**8-1)
    
        self.mock_g_index.pack(gIndex, p)
        self.simulated_g_index.pack(gIndex, p)
        assert self.mock_g_index.unwrap() == self.simulated_g_index.value
        logger.info(f"PACK ASSERT {self.mock_g_index.unwrap()} == {self.simulated_g_index.value}")

    @flow(weight=1000)
    def flow_shr(self):
        shift_right = random_int(0, self.simulated_g_index.width())
        if ( ( (self.mock_g_index.index() % self.mock_g_index.width()) + shift_right) >= self.mock_g_index.width()):
            with must_revert(MockGIndex.IndexOutOfRangeShift()):
                self.mock_g_index.shr(shift_right)
            logger.info(f"SHR REVERTED: shr n={shift_right}; index={self.mock_g_index.index()}; width={self.mock_g_index.width()}")
        else:
            mockValue = self.mock_g_index.shr(shift_right)
            simulated_value = self.simulated_g_index.shift_right(shift_right)
            logger.info(f"SHR ASSERT {mockValue} == {simulated_value}")       
            assert mockValue == simulated_value

    @flow(weight=1000)
    def flow_shl(self):
        shift_left = random_int(0, self.simulated_g_index.width())
        if ( (self.mock_g_index.index() % self.mock_g_index.width()) < shift_left):
            with must_revert(MockGIndex.IndexOutOfRangeShift()):
                self.mock_g_index.shl(shift_left)
            logger.info(f"SHL REVERTED: shr n={shift_left}; index={self.mock_g_index.index()}; width={self.mock_g_index.width()}")
        else:
            mockValue = self.mock_g_index.shl(shift_left)
            simulated_value = self.simulated_g_index.shift_left(shift_left)
            logger.info(f"SHL ASSERT {mockValue} == {simulated_value}")       
            assert mockValue == simulated_value

    @flow(weight=10000)
    def flow_fls(self):
        power = random_int(0,255)
        residue = random_int(0, power-1) if power != 0 else random_int(0, 1)  
        uint_to_check = random_int(0,2**power) + residue
        assert self.most_significant_bit_index(uint_to_check) == self.mock_g_index.fls(uint_to_check)
        logger.info(f"FLS valid: uint_to_check = {uint_to_check}; TRUE: {self.most_significant_bit_index(uint_to_check)} == {self.mock_g_index.fls(uint_to_check)}")

    @flow(weight=1000)
    def flow_concatanetation(self):
        random_power = random_int(0,247)
        gI = random_int(0, 2**random_power)
        p = random_int(0,255)
        self.first_simulated_g_index.pack(gI,p)
        self.first_mock_g_index.pack(gI,p)

        random_power = random_int(0,247)
        gI = random_int(0, 2**random_power)
        p = random_int(0,255)
        self.second_simulated_g_index.pack(gI, p)
        self.second_mock_g_index.pack(gI, p)

        if self.most_significant_bit_index(self.first_simulated_g_index.index()) > self.most_significant_bit_index(self.second_simulated_g_index.index()):
            tmp = self.first_simulated_g_index
            self.first_simulated_g_index = self.second_simulated_g_index
            self.second_simulated_g_index = tmp

            tmp = self.first_mock_g_index
            self.first_mock_g_index = self.second_mock_g_index
            self.second_mock_g_index = tmp

        concatenation_mock: TransactionAbc
        try: 
            concatenation_simulation = self.concat_gindices(self.first_simulated_g_index, self.second_simulated_g_index)
            concatenation_mock = self.mock_g_index.concat(self.first_mock_g_index.unwrap(), self.second_mock_g_index.unwrap())
        except (IndexesOverflow, ValueOverflow) as e :
            with must_revert( (MockGIndex.IndexOutOfRangeConcat, MockGIndex.IndexOutOfRangePack)):
                concatenation_mock = self.mock_g_index.concat(self.first_mock_g_index.unwrap() ,self.second_mock_g_index.unwrap())
            return
        logger.info(f"CONC ASSERT: {concatenation_simulation} == {concatenation_mock}")

        assert concatenation_simulation == concatenation_mock


@default_chain.connect(accounts=20)
def test_csm():
    GIndexFuzz().run(10000, 100)

