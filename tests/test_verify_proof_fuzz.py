import logging
from typing import Tuple
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.csm.src.lib.SSZ import SSZ
from .merkle_tree import MerkleTree

from pytypes.tests.helpers.MockSSZ import MockSZZ
import math


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class SzzVerifyProofFuzzTest(FuzzTest):
    
    mock_ssz: MockSZZ
    def pre_sequence(self) -> None:
        self.mock_ssz = MockSZZ.deploy()

    def generate_random_merkle_tree(self) -> Tuple[MerkleTree, List[bytes], int]:
        tmp_merkle_tree = MerkleTree(hash_func="sha256",hash_leaves=False, sort_pairs=False)
        hashes_list = []
        number_of_leaves = random_int(1, 1_000_00)

        for _ in range(number_of_leaves):
            leaf_value = random_bytes(32)
            hashes_list.append(leaf_value)
            tmp_merkle_tree.add_leaf(leaf_value)
            # logger.info(f"added leaf: {leaf_value.hex()}")
        return tmp_merkle_tree, hashes_list, number_of_leaves 
    
    @staticmethod
    def log2_ceil(x):
        return math.ceil(math.log2(x))

    @flow()
    def flow_verify_proof(self):
        (merkle_tree, list_of_gindex, count_of_leaves) = self.generate_random_merkle_tree()
        width_of_tree = (self.log2_ceil(count_of_leaves))
        random_index = random_int(0,count_of_leaves-1)
        logger.info(f"random_index = {random_index}; decomposition: {bin(random_index+ 2**width_of_tree)}")
        
        g_index = (( (random_index + 2**width_of_tree) << 8) | width_of_tree)
        g_index_encoded = g_index.to_bytes(32,"big")
        logger.info(f"g_index = {g_index_encoded}")

        proof_for_specific_index = merkle_tree.get_proof(random_index)
        root_of_tree = merkle_tree.root

        random_check = random.choice(["valid", "gindex", "proof"])

        if random_check == "valid":
            self.mock_ssz.testVerifyProof(proof=proof_for_specific_index,
                                    root=root_of_tree,
                                    leaf=list_of_gindex[random_index],
                                    gIndex=g_index_encoded
                                    )
            logger.warning("check for 'valid' succeed")
        elif random_check == "gindex":
            invalid_random_index = random_int(0,count_of_leaves-1) 
            while invalid_random_index == random_index: invalid_random_index = random_int(0,count_of_leaves-1)
            invalid_g_index_encoded =  (( (invalid_random_index + 2**width_of_tree) << 8) | width_of_tree).to_bytes(32,"big")
            with must_revert(UnknownTransactionRevertedError(data=b'\t\xbd\xe39')):
                self.mock_ssz.testVerifyProof(proof=proof_for_specific_index,
                            root=root_of_tree,
                            leaf=list_of_gindex[random_index],
                            gIndex=invalid_g_index_encoded
                            )
            logger.info("check for 'invalid gindex' because of invalid gIndex succeed")
        
        elif random_check == "proof":
            invalid_random_index = random_int(0,count_of_leaves-1) 
            while invalid_random_index == random_index: invalid_random_index = random_int(0,count_of_leaves-1)
            invalid_random_proof = merkle_tree.get_proof(invalid_random_index)
            with must_revert(UnknownTransactionRevertedError(data=b'\t\xbd\xe39')):
                self.mock_ssz.testVerifyProof(proof=invalid_random_proof,
                            root=root_of_tree,
                            leaf=list_of_gindex[random_index],
                            gIndex=g_index_encoded
                            )
            logger.warning("check for 'invalid proof' because of invalid proof succeed")


@default_chain.connect(accounts=20)
def test_csm():
    SzzVerifyProofFuzzTest().run(10000, 100)