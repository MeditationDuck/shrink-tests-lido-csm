// SPDX-FileCopyrightText: 2024 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.24;

import {GIndex} from "../../csm/src/lib/GIndex.sol";

import "wake/console.sol";


contract MockGIndex{

    GIndex g_index;
    error IndexOutOfRangeShift();
    error IndexOutOfRangeConcat();
    error IndexOutOfRangePack();


    function pack(uint256 gI, uint8 p) public returns (GIndex) {
        if (gI > type(uint248).max) {
            revert IndexOutOfRangePack();
        }

        g_index = GIndex.wrap(bytes32((gI << 8) | p));
        return GIndex.wrap(bytes32((gI << 8) | p));
    }

    function pack_without_changing(uint256 gI, uint8 p) public view returns (GIndex) {
        if (gI > type(uint248).max) {
            revert IndexOutOfRangePack();
        }

        console.log("number: ", (gI << 8) | p);
        return GIndex.wrap(bytes32((gI << 8) | p));
    }

    function unwrap() public view returns (bytes32) {
        return GIndex.unwrap(g_index);
    }

    function helper_func() public view returns (uint256){
        return index() % width(); 
    }

    function index() public view returns (uint256) {
        return uint256(unwrap()) >> 8;
    }

    function isRoot() public view returns (bool) {
        return index() == 1;
    }

    function width() public view returns (uint256) {
        return 1 << pow();
    }

    function pow() public view returns (uint8) {
        return uint8(uint256(unwrap()));
    }

    /// @return Generalized index of the nth neighbor of the node to the right.
    function shr(uint256 n) public view returns (GIndex) {
        uint256 i = index();
        uint256 w = width();

        if ((i % w) + n >= w) {
            revert IndexOutOfRangeShift();
        }
        return pack_without_changing(i + n, pow());
    }

    /// @return Generalized index of the nth neighbor of the node to the left.
    function shl(uint256 n) public view returns (GIndex) {
        uint256 i = index();
        uint256 w = width();

        if (i % w < n) {
            revert IndexOutOfRangeShift();
        }
        return pack_without_changing(i - n, pow());
    }

    function fls(uint256 x) public pure returns (uint256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            // prettier-ignore
            r := or(shl(8, iszero(x)), shl(7, lt(0xffffffffffffffffffffffffffffffff, x)))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))
            // prettier-ignore
            r := or(r, byte(and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
                    0x0706060506020504060203020504030106050205030304010505030400000000))
        }
    }

    function concat(GIndex lhs, GIndex rhs) public view returns (GIndex) {

        uint256 lhsMSbIndex = fls(lhs.index());
        uint256 rhsMSbIndex = fls(rhs.index());

        if (lhsMSbIndex + 1 + rhsMSbIndex > 248) {
            revert IndexOutOfRangeConcat();
        }
        
        return
            pack_without_changing(
                (lhs.index() << rhsMSbIndex) | (rhs.index() ^ (1 << rhsMSbIndex)), rhs.pow()
            );
    }

}