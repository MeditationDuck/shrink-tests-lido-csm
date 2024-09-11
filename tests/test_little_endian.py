import logging
from pytypes.tests.helpers.MockLittleEndian import MockLittleEndian
from wake.testing import *
from wake.testing.fuzzing import *



logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class toLittleEndianFuzzTest(FuzzTest):
    
    little_endian: MockLittleEndian

    def pre_sequence(self):
        self.little_endian = MockLittleEndian.deploy()

    @flow()
    def big_to_little_endian(self):
        value = random_bytes(32)
        value_number = int.from_bytes(value, byteorder="big")
        assert self.little_endian.mock_toLittleEndian(value_number) == value[::-1]

@chain.connect(fork="http://localhost:8545", accounts=20)
def test_csm():
    toLittleEndianFuzzTest().run(1, 1000000)

