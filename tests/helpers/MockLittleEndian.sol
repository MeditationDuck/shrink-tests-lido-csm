// SPDX-License-Identifier: MIT
import "../../csm/src/lib/SSZ.sol";


contract MockLittleEndian {
    using SSZ for uint256;

    function mock_toLittleEndian(uint256 v) external pure returns(bytes32){
        return v.toLittleEndian();
    }
}