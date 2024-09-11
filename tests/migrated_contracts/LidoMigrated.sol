// SPDX-FileCopyrightText: 2023 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0

/* See contracts/COMPILERS.md */
pragma solidity ^0.6.2;

import "./aragon/os/apps/AragonApp.sol";
import "./aragon/os/lib/math/SafeMath.sol";
import "./aragon/os/common/UnstructuredStorage.sol";

import "../../core/contracts/common/interfaces/ILidoLocator.sol";
import "../../core/contracts/common/interfaces/IBurner.sol";
import "../../core/contracts/common/lib/Math256.sol";
import "../../core/contracts/common/lib/SignatureUtils.sol";
import "../../core/contracts/common/interfaces/IEIP712StETH.sol";

import "./utils_and_lib/Versioned.sol";
import "./utils_and_lib/Pausable.sol";

import "wake/console.sol";

library StakeLimitState {
    /**
      * @dev Internal representation struct (slot-wide)
      */
    struct Data {
        uint32 prevStakeBlockNumber;      // block number of the previous stake submit
        uint96 prevStakeLimit;            // limit value (<= `maxStakeLimit`) obtained on the previous stake submit
        uint32 maxStakeLimitGrowthBlocks; // limit regeneration speed expressed in blocks
        uint96 maxStakeLimit;             // maximum limit value
    }
}

library StakeLimitUnstructuredStorage {
    using UnstructuredStorage for bytes32;

    /// @dev Storage offset for `maxStakeLimit` (bits)
    uint256 internal constant MAX_STAKE_LIMIT_OFFSET = 160;
    /// @dev Storage offset for `maxStakeLimitGrowthBlocks` (bits)
    uint256 internal constant MAX_STAKE_LIMIT_GROWTH_BLOCKS_OFFSET = 128;
    /// @dev Storage offset for `prevStakeLimit` (bits)
    uint256 internal constant PREV_STAKE_LIMIT_OFFSET = 32;
    /// @dev Storage offset for `prevStakeBlockNumber` (bits)
    uint256 internal constant PREV_STAKE_BLOCK_NUMBER_OFFSET = 0;

    /**
    * @dev Read stake limit state from the unstructured storage position
    * @param _position storage offset
    */
    function getStorageStakeLimitStruct(bytes32 _position) internal view returns (StakeLimitState.Data memory stakeLimit) {
        uint256 slotValue = _position.getStorageUint256();

        stakeLimit.prevStakeBlockNumber = uint32(slotValue >> PREV_STAKE_BLOCK_NUMBER_OFFSET);
        stakeLimit.prevStakeLimit = uint96(slotValue >> PREV_STAKE_LIMIT_OFFSET);
        stakeLimit.maxStakeLimitGrowthBlocks = uint32(slotValue >> MAX_STAKE_LIMIT_GROWTH_BLOCKS_OFFSET);
        stakeLimit.maxStakeLimit = uint96(slotValue >> MAX_STAKE_LIMIT_OFFSET);
    }

     /**
    * @dev Write stake limit state to the unstructured storage position
    * @param _position storage offset
    * @param _data stake limit state structure instance
    */
    function setStorageStakeLimitStruct(bytes32 _position, StakeLimitState.Data memory _data) internal {
        _position.setStorageUint256(
            uint256(_data.prevStakeBlockNumber) << PREV_STAKE_BLOCK_NUMBER_OFFSET
                | uint256(_data.prevStakeLimit) << PREV_STAKE_LIMIT_OFFSET
                | uint256(_data.maxStakeLimitGrowthBlocks) << MAX_STAKE_LIMIT_GROWTH_BLOCKS_OFFSET
                | uint256(_data.maxStakeLimit) << MAX_STAKE_LIMIT_OFFSET
        );
    }
}

/**
* @notice Interface library with helper functions to deal with stake limit struct in a more high-level approach.
*/
library StakeLimitUtils {
    /**
    * @notice Calculate stake limit for the current block.
    * @dev using `_constGasMin` to make gas consumption independent of the current block number
    */
    function calculateCurrentStakeLimit(StakeLimitState.Data memory _data) internal view returns(uint256 limit) {
        uint256 stakeLimitIncPerBlock;
        if (_data.maxStakeLimitGrowthBlocks != 0) {
            stakeLimitIncPerBlock = _data.maxStakeLimit / _data.maxStakeLimitGrowthBlocks;
        }

        uint256 blocksPassed = block.number - _data.prevStakeBlockNumber;
        uint256 projectedLimit = _data.prevStakeLimit + blocksPassed * stakeLimitIncPerBlock;

        limit = _constGasMin(
            projectedLimit,
            _data.maxStakeLimit
        );
    }

    /**
    * @notice check if staking is on pause
    */
    function isStakingPaused(StakeLimitState.Data memory _data) internal pure returns(bool) {
        return _data.prevStakeBlockNumber == 0;
    }

    /**
    * @notice check if staking limit is set (otherwise staking is unlimited)
    */
    function isStakingLimitSet(StakeLimitState.Data memory _data) internal pure returns(bool) {
        return _data.maxStakeLimit != 0;
    }

    /**
    * @notice update stake limit repr with the desired limits
    * @dev input `_data` param is mutated and the func returns effectively the same pointer
    * @param _data stake limit state struct
    * @param _maxStakeLimit stake limit max value
    * @param _stakeLimitIncreasePerBlock stake limit increase (restoration) per block
    */
    function setStakingLimit(
        StakeLimitState.Data memory _data,
        uint256 _maxStakeLimit,
        uint256 _stakeLimitIncreasePerBlock
    ) internal view returns (StakeLimitState.Data memory) {
        require(_maxStakeLimit != 0, "ZERO_MAX_STAKE_LIMIT");
        require(_maxStakeLimit <= uint96(-1), "TOO_LARGE_MAX_STAKE_LIMIT");
        require(_maxStakeLimit >= _stakeLimitIncreasePerBlock, "TOO_LARGE_LIMIT_INCREASE");
        require(
            (_stakeLimitIncreasePerBlock == 0)
            || (_maxStakeLimit / _stakeLimitIncreasePerBlock <= uint32(-1)),
            "TOO_SMALL_LIMIT_INCREASE"
        );

        // reset prev stake limit to the new max stake limit if
        if (
            // staking was paused or
            _data.prevStakeBlockNumber == 0 ||
            // staking was unlimited or
            _data.maxStakeLimit == 0 ||
            // new maximum limit value is lower than the value obtained on the previous stake submit
            _maxStakeLimit < _data.prevStakeLimit
        ) {
            _data.prevStakeLimit = uint96(_maxStakeLimit);
        }
        _data.maxStakeLimitGrowthBlocks =
            _stakeLimitIncreasePerBlock != 0 ? uint32(_maxStakeLimit / _stakeLimitIncreasePerBlock) : 0;

        _data.maxStakeLimit = uint96(_maxStakeLimit);

        if (_data.prevStakeBlockNumber != 0) {
            _data.prevStakeBlockNumber = uint32(block.number);
        }

        return _data;
    }

    /**
    * @notice update stake limit repr to remove the limit
    * @dev input `_data` param is mutated and the func returns effectively the same pointer
    * @param _data stake limit state struct
    */
    function removeStakingLimit(
        StakeLimitState.Data memory _data
    ) internal pure returns (StakeLimitState.Data memory) {
        _data.maxStakeLimit = 0;

        return _data;
    }

    /**
    * @notice update stake limit repr after submitting user's eth
    * @dev input `_data` param is mutated and the func returns effectively the same pointer
    * @param _data stake limit state struct
    * @param _newPrevStakeLimit new value for the `prevStakeLimit` field
    */
    function updatePrevStakeLimit(
        StakeLimitState.Data memory _data,
        uint256 _newPrevStakeLimit
    ) internal view returns (StakeLimitState.Data memory) {
        assert(_newPrevStakeLimit <= uint96(-1));
        assert(_data.prevStakeBlockNumber != 0);

        _data.prevStakeLimit = uint96(_newPrevStakeLimit);
        _data.prevStakeBlockNumber = uint32(block.number);

        return _data;
    }

    /**
    * @notice set stake limit pause state (on or off)
    * @dev input `_data` param is mutated and the func returns effectively the same pointer
    * @param _data stake limit state struct
    * @param _isPaused pause state flag
    */
    function setStakeLimitPauseState(
        StakeLimitState.Data memory _data,
        bool _isPaused
    ) internal view returns (StakeLimitState.Data memory) {
        _data.prevStakeBlockNumber = uint32(_isPaused ? 0 : block.number);

        return _data;
    }

    /**
     * @notice find a minimum of two numbers with a constant gas consumption
     * @dev doesn't use branching logic inside
     * @param _lhs left hand side value
     * @param _rhs right hand side value
     */
    function _constGasMin(uint256 _lhs, uint256 _rhs) internal pure returns (uint256 min) {
        uint256 lhsIsLess;
        assembly {
            lhsIsLess := lt(_lhs, _rhs) // lhsIsLess = (_lhs < _rhs) ? 1 : 0
        }
        min = (_lhs * lhsIsLess) + (_rhs * (1 - lhsIsLess));
    }
}


interface IERC20 {
  function totalSupply() external view returns (uint256);

  function balanceOf(address who) external view returns (uint256);

  function allowance(address owner, address spender)
    external view returns (uint256);

  function transfer(address to, uint256 value) external returns (bool);

  function approve(address spender, uint256 value)
    external returns (bool);

  function transferFrom(address from, address to, uint256 value)
    external returns (bool);

  event Transfer(
    address indexed from,
    address indexed to,
    uint256 value
  );

  event Approval(
    address indexed owner,
    address indexed spender,
    uint256 value
  );
}


abstract contract StETH is IERC20, Pausable {
  using SafeMath for uint256;
  using UnstructuredStorage for bytes32;

  address internal constant INITIAL_TOKEN_HOLDER = address(0xdead);
  uint256 internal constant INFINITE_ALLOWANCE = ~uint256(0);

  /**
   * @dev StETH balances are dynamic and are calculated based on the accounts' shares
   * and the total amount of Ether controlled by the protocol. Account shares aren't
   * normalized, so the contract also stores the sum of all shares to calculate
   * each account's token balance which equals to:
   *
   *   shares[account] * _getTotalPooledEther() / _getTotalShares()
   */
  mapping(address => uint256) private shares;

  /**
   * @dev Allowances are nominated in tokens, not token shares.
   */
  mapping(address => mapping(address => uint256)) private allowances;

  /**
   * @dev Storage position used for holding the total amount of shares in existence.
   *
   * The Lido protocol is built on top of Aragon and uses the Unstructured Storage pattern
   * for value types:
   *
   * https://blog.openzeppelin.com/upgradeability-using-unstructured-storage
   * https://blog.8bitzen.com/posts/20-02-2020-understanding-how-solidity-upgradeable-unstructured-proxies-work
   *
   * For reference types, conventional storage variables are used since it's non-trivial
   * and error-prone to implement reference-type unstructured storage using Solidity v0.4;
   * see https://github.com/lidofinance/lido-dao/issues/181#issuecomment-736098834
   *
   * keccak256("lido.StETH.totalShares")
   */
  bytes32 internal constant TOTAL_SHARES_POSITION = 0xe3b4b636e601189b5f4c6742edf2538ac12bb61ed03e6da26949d69838fa447e;

  /**
   * @notice An executed shares transfer from `sender` to `recipient`.
   *
   * @dev emitted in pair with an ERC20-defined `Transfer` event.
   */
  event TransferShares(address indexed from, address indexed to, uint256 sharesValue);

  /**
   * @notice An executed `burnShares` request
   *
   * @dev Reports simultaneously burnt shares amount
   * and corresponding stETH amount.
   * The stETH amount is calculated twice: before and after the burning incurred rebase.
   *
   * @param account holder of the burnt shares
   * @param preRebaseTokenAmount amount of stETH the burnt shares corresponded to before the burn
   * @param postRebaseTokenAmount amount of stETH the burnt shares corresponded to after the burn
   * @param sharesAmount amount of burnt shares
   */
  event SharesBurnt(
    address indexed account,
    uint256 preRebaseTokenAmount,
    uint256 postRebaseTokenAmount,
    uint256 sharesAmount
  );

  /**
   * @return the name of the token.
   */
  function name() external pure returns (string memory) {
    return "Liquid staked Ether 2.0";
  }

  /**
   * @return the symbol of the token, usually a shorter version of the
   * name.
   */
  function symbol() external pure returns (string memory) {
    return "stETH";
  }

  /**
   * @return the number of decimals for getting user representation of a token amount.
   */
  function decimals() external pure returns (uint8) {
    return 18;
  }

  /**
   * @return the amount of tokens in existence.
   *
   * @dev Always equals to `_getTotalPooledEther()` since token amount
   * is pegged to the total amount of Ether controlled by the protocol.
   */
  function totalSupply() external view override returns (uint256) {
    return _getTotalPooledEther();
  }

  /**
   * @return the entire amount of Ether controlled by the protocol.
   *
   * @dev The sum of all ETH balances in the protocol, equals to the total supply of stETH.
   */
  function getTotalPooledEther() external view returns (uint256) {
    return _getTotalPooledEther();
  }

  /**
   * @return the amount of tokens owned by the `_account`.
   *
   * @dev Balances are dynamic and equal the `_account`'s share in the amount of the
   * total Ether controlled by the protocol. See `sharesOf`.
   */
  function balanceOf(address _account) external view override returns (uint256) {
    return getPooledEthByShares(_sharesOf(_account));
  }

  /**
   * @notice Moves `_amount` tokens from the caller's account to the `_recipient` account.
   *
   * @return a boolean value indicating whether the operation succeeded.
   * Emits a `Transfer` event.
   * Emits a `TransferShares` event.
   *
   * Requirements:
   *
   * - `_recipient` cannot be the zero address.
   * - the caller must have a balance of at least `_amount`.
   * - the contract must not be paused.
   *
   * @dev The `_amount` argument is the amount of tokens, not shares.
   */
  function transfer(address _recipient, uint256 _amount) external override returns (bool) {
    _transfer(msg.sender, _recipient, _amount);
    return true;
  }

  /**
   * @return the remaining number of tokens that `_spender` is allowed to spend
   * on behalf of `_owner` through `transferFrom`. This is zero by default.
   *
   * @dev This value changes when `approve` or `transferFrom` is called.
   */
  function allowance(address _owner, address _spender) external view override returns (uint256) {
    return allowances[_owner][_spender];
  }

  /**
   * @notice Sets `_amount` as the allowance of `_spender` over the caller's tokens.
   *
   * @return a boolean value indicating whether the operation succeeded.
   * Emits an `Approval` event.
   *
   * Requirements:
   *
   * - `_spender` cannot be the zero address.
   *
   * @dev The `_amount` argument is the amount of tokens, not shares.
   */
  function approve(address _spender, uint256 _amount) external override returns (bool) {
    _approve(msg.sender, _spender, _amount);
    return true;
  }

  /**
   * @notice Moves `_amount` tokens from `_sender` to `_recipient` using the
   * allowance mechanism. `_amount` is then deducted from the caller's
   * allowance.
   *
   * @return a boolean value indicating whether the operation succeeded.
   *
   * Emits a `Transfer` event.
   * Emits a `TransferShares` event.
   * Emits an `Approval` event indicating the updated allowance.
   *
   * Requirements:
   *
   * - `_sender` and `_recipient` cannot be the zero addresses.
   * - `_sender` must have a balance of at least `_amount`.
   * - the caller must have allowance for `_sender`'s tokens of at least `_amount`.
   * - the contract must not be paused.
   *
   * @dev The `_amount` argument is the amount of tokens, not shares.
   */
  function transferFrom(address _sender, address _recipient, uint256 _amount) external override returns (bool) {
    _spendAllowance(_sender, msg.sender, _amount);
    _transfer(_sender, _recipient, _amount);
    return true;
  }

  /**
   * @notice Atomically increases the allowance granted to `_spender` by the caller by `_addedValue`.
   *
   * This is an alternative to `approve` that can be used as a mitigation for
   * problems described in:
   * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/b709eae01d1da91902d06ace340df6b324e6f049/contracts/token/ERC20/IERC20.sol#L57
   * Emits an `Approval` event indicating the updated allowance.
   *
   * Requirements:
   *
   * - `_spender` cannot be the the zero address.
   */
  function increaseAllowance(address _spender, uint256 _addedValue) external returns (bool) {
    _approve(msg.sender, _spender, allowances[msg.sender][_spender].add(_addedValue));
    return true;
  }

  /**
   * @notice Atomically decreases the allowance granted to `_spender` by the caller by `_subtractedValue`.
   *
   * This is an alternative to `approve` that can be used as a mitigation for
   * problems described in:
   * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/b709eae01d1da91902d06ace340df6b324e6f049/contracts/token/ERC20/IERC20.sol#L57
   * Emits an `Approval` event indicating the updated allowance.
   *
   * Requirements:
   *
   * - `_spender` cannot be the zero address.
   * - `_spender` must have allowance for the caller of at least `_subtractedValue`.
   */
  function decreaseAllowance(address _spender, uint256 _subtractedValue) external returns (bool) {
    uint256 currentAllowance = allowances[msg.sender][_spender];
    require(currentAllowance >= _subtractedValue, "ALLOWANCE_BELOW_ZERO");
    _approve(msg.sender, _spender, currentAllowance.sub(_subtractedValue));
    return true;
  }

  /**
   * @return the total amount of shares in existence.
   *
   * @dev The sum of all accounts' shares can be an arbitrary number, therefore
   * it is necessary to store it in order to calculate each account's relative share.
   */
  function getTotalShares() external view returns (uint256) {
    return _getTotalShares();
  }

  /**
   * @return the amount of shares owned by `_account`.
   */
  function sharesOf(address _account) external view returns (uint256) {
    return _sharesOf(_account);
  }

  /**
   * @return the amount of shares that corresponds to `_ethAmount` protocol-controlled Ether.
   */
  function getSharesByPooledEth(uint256 _ethAmount) public view returns (uint256) {
    return _ethAmount.mul(_getTotalShares()).div(_getTotalPooledEther());
  }

  /**
   * @return the amount of Ether that corresponds to `_sharesAmount` token shares.
   */
  function getPooledEthByShares(uint256 _sharesAmount) public view returns (uint256) {
    return _sharesAmount.mul(_getTotalPooledEther()).div(_getTotalShares());
  }

  /**
   * @notice Moves `_sharesAmount` token shares from the caller's account to the `_recipient` account.
   *
   * @return amount of transferred tokens.
   * Emits a `TransferShares` event.
   * Emits a `Transfer` event.
   *
   * Requirements:
   *
   * - `_recipient` cannot be the zero address.
   * - the caller must have at least `_sharesAmount` shares.
   * - the contract must not be paused.
   *
   * @dev The `_sharesAmount` argument is the amount of shares, not tokens.
   */
  function transferShares(address _recipient, uint256 _sharesAmount) external returns (uint256) {
    _transferShares(msg.sender, _recipient, _sharesAmount);
    uint256 tokensAmount = getPooledEthByShares(_sharesAmount);
    _emitTransferEvents(msg.sender, _recipient, tokensAmount, _sharesAmount);
    return tokensAmount;
  }

  /**
   * @notice Moves `_sharesAmount` token shares from the `_sender` account to the `_recipient` account.
   *
   * @return amount of transferred tokens.
   * Emits a `TransferShares` event.
   * Emits a `Transfer` event.
   *
   * Requirements:
   *
   * - `_sender` and `_recipient` cannot be the zero addresses.
   * - `_sender` must have at least `_sharesAmount` shares.
   * - the caller must have allowance for `_sender`'s tokens of at least `getPooledEthByShares(_sharesAmount)`.
   * - the contract must not be paused.
   *
   * @dev The `_sharesAmount` argument is the amount of shares, not tokens.
   */
  function transferSharesFrom(address _sender, address _recipient, uint256 _sharesAmount) external returns (uint256) {
    uint256 tokensAmount = getPooledEthByShares(_sharesAmount);
    _spendAllowance(_sender, msg.sender, tokensAmount);
    _transferShares(_sender, _recipient, _sharesAmount);
    _emitTransferEvents(_sender, _recipient, tokensAmount, _sharesAmount);
    return tokensAmount;
  }

  /**
   * @notice Moves `_amount` tokens from `_sender` to `_recipient`.
   * Emits a `Transfer` event.
   * Emits a `TransferShares` event.
   */
  function _transfer(address _sender, address _recipient, uint256 _amount) internal {
    uint256 _sharesToTransfer = getSharesByPooledEth(_amount);
    _transferShares(_sender, _recipient, _sharesToTransfer);
    _emitTransferEvents(_sender, _recipient, _amount, _sharesToTransfer);
  }

  /**
   * @notice Sets `_amount` as the allowance of `_spender` over the `_owner` s tokens.
   *
   * Emits an `Approval` event.
   *
   * NB: the method can be invoked even if the protocol paused.
   *
   * Requirements:
   *
   * - `_owner` cannot be the zero address.
   * - `_spender` cannot be the zero address.
   */
  function _approve(address _owner, address _spender, uint256 _amount) internal {
    require(_owner != address(0), "APPROVE_FROM_ZERO_ADDR");
    require(_spender != address(0), "APPROVE_TO_ZERO_ADDR");

    allowances[_owner][_spender] = _amount;
    emit Approval(_owner, _spender, _amount);
  }

  /**
   * @dev Updates `owner` s allowance for `spender` based on spent `amount`.
   *
   * Does not update the allowance amount in case of infinite allowance.
   * Revert if not enough allowance is available.
   *
   * Might emit an {Approval} event.
   */
  function _spendAllowance(address _owner, address _spender, uint256 _amount) internal {
    uint256 currentAllowance = allowances[_owner][_spender];
    if (currentAllowance != INFINITE_ALLOWANCE) {
      require(currentAllowance >= _amount, "ALLOWANCE_EXCEEDED");
      _approve(_owner, _spender, currentAllowance - _amount);
    }
  }

  /**
   * @return the total amount of shares in existence.
   */
  function _getTotalShares() internal view returns (uint256) {
    return TOTAL_SHARES_POSITION.getStorageUint256();
  }

  /**
   * @return the amount of shares owned by `_account`.
   */
  function _sharesOf(address _account) internal view returns (uint256) {
    return shares[_account];
  }

  /**
   * @notice Moves `_sharesAmount` shares from `_sender` to `_recipient`.
   *
   * Requirements:
   *
   * - `_sender` cannot be the zero address.
   * - `_recipient` cannot be the zero address or the `stETH` token contract itself
   * - `_sender` must hold at least `_sharesAmount` shares.
   * - the contract must not be paused.
   */
  function _transferShares(address _sender, address _recipient, uint256 _sharesAmount) internal {
    require(_sender != address(0), "TRANSFER_FROM_ZERO_ADDR");
    require(_recipient != address(0), "TRANSFER_TO_ZERO_ADDR");
    require(_recipient != address(this), "TRANSFER_TO_STETH_CONTRACT");
    _whenNotStopped();

    uint256 currentSenderShares = shares[_sender];
    require(_sharesAmount <= currentSenderShares, "BALANCE_EXCEEDED");

    shares[_sender] = currentSenderShares.sub(_sharesAmount);
    shares[_recipient] = shares[_recipient].add(_sharesAmount);
  }

  /**
   * @notice Creates `_sharesAmount` shares and assigns them to `_recipient`, increasing the total amount of shares.
   * @dev This doesn't increase the token total supply.
   *
   * NB: The method doesn't check protocol pause relying on the external enforcement.
   *
   * Requirements:
   *
   * - `_recipient` cannot be the zero address.
   * - the contract must not be paused.
   */
  function _mintShares(address _recipient, uint256 _sharesAmount) internal returns (uint256 newTotalShares) {
    require(_recipient != address(0), "MINT_TO_ZERO_ADDR");

    newTotalShares = _getTotalShares().add(_sharesAmount);
    TOTAL_SHARES_POSITION.setStorageUint256(newTotalShares);

    shares[_recipient] = shares[_recipient].add(_sharesAmount);

    // Notice: we're not emitting a Transfer event from the zero address here since shares mint
    // works by taking the amount of tokens corresponding to the minted shares from all other
    // token holders, proportionally to their share. The total supply of the token doesn't change
    // as the result. This is equivalent to performing a send from each other token holder's
    // address to `address`, but we cannot reflect this as it would require sending an unbounded
    // number of events.
  }

  /**
   * @notice Destroys `_sharesAmount` shares from `_account`'s holdings, decreasing the total amount of shares.
   * @dev This doesn't decrease the token total supply.
   *
   * Requirements:
   *
   * - `_account` cannot be the zero address.
   * - `_account` must hold at least `_sharesAmount` shares.
   * - the contract must not be paused.
   */
  function _burnShares(address _account, uint256 _sharesAmount) internal returns (uint256 newTotalShares) {
    require(_account != address(0), "BURN_FROM_ZERO_ADDR");

    uint256 accountShares = shares[_account];
    require(_sharesAmount <= accountShares, "BALANCE_EXCEEDED");

    uint256 preRebaseTokenAmount = getPooledEthByShares(_sharesAmount);

    newTotalShares = _getTotalShares().sub(_sharesAmount);
    TOTAL_SHARES_POSITION.setStorageUint256(newTotalShares);

    shares[_account] = accountShares.sub(_sharesAmount);

    uint256 postRebaseTokenAmount = getPooledEthByShares(_sharesAmount);

    emit SharesBurnt(_account, preRebaseTokenAmount, postRebaseTokenAmount, _sharesAmount);

    // Notice: we're not emitting a Transfer event to the zero address here since shares burn
    // works by redistributing the amount of tokens corresponding to the burned shares between
    // all other token holders. The total supply of the token doesn't change as the result.
    // This is equivalent to performing a send from `address` to each other token holder address,
    // but we cannot reflect this as it would require sending an unbounded number of events.

    // We're emitting `SharesBurnt` event to provide an explicit rebase log record nonetheless.
  }

  /**
   * @dev Emits {Transfer} and {TransferShares} events
   */
  function _emitTransferEvents(address _from, address _to, uint _tokenAmount, uint256 _sharesAmount) internal {
    emit Transfer(_from, _to, _tokenAmount);
    emit TransferShares(_from, _to, _sharesAmount);
  }

  /**
   * @dev Emits {Transfer} and {TransferShares} events where `from` is 0 address. Indicates mint events.
   */
  function _emitTransferAfterMintingShares(address _to, uint256 _sharesAmount) internal {
    _emitTransferEvents(address(0), _to, getPooledEthByShares(_sharesAmount), _sharesAmount);
  }

  /**
   * @dev Mints shares to INITIAL_TOKEN_HOLDER
   */
  function _mintInitialShares(uint256 _sharesAmount) internal {
    _mintShares(INITIAL_TOKEN_HOLDER, _sharesAmount);
    _emitTransferAfterMintingShares(INITIAL_TOKEN_HOLDER, _sharesAmount);
  }

  function _getTotalPooledEther() internal view virtual returns (uint256) {}
}


/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */
interface IERC2612 {
    /**
     * @dev Sets `value` as the allowance of `spender` over ``owner``'s tokens,
     * given ``owner``'s signed approval.
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `deadline` must be a timestamp in the future.
     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
     * over the EIP712-formatted function arguments.
     * - the signature must use ``owner``'s current nonce (see {nonces}).
     */
    function permit(
        address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external;

    /**
     * @dev Returns the current nonce for `owner`. This value must be
     * included whenever a signature is generated for {permit}.
     *
     * Every successful call to {permit} increases ``owner``'s nonce by one. This
     * prevents a signature from being used multiple times.
     */
    function nonces(address owner) external view returns (uint256);

    /**
     * @dev Returns the domain separator used in the encoding of the signature for {permit}, as defined by {EIP712}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}


contract StETHPermit is IERC2612, StETH {
    using UnstructuredStorage for bytes32;

    /**
     * @dev Service event for initialization
     */
    event EIP712StETHInitialized(address eip712StETH);

    /**
     * @dev Nonces for ERC-2612 (Permit)
     */
    mapping(address => uint256) internal noncesByAddress;

    /**
     * @dev Storage position used for the EIP712 message utils contract
     *
     * keccak256("lido.StETHPermit.eip712StETH")
     */
    bytes32 internal constant EIP712_STETH_POSITION =
        0x42b2d95e1ce15ce63bf9a8d9f6312cf44b23415c977ffa3b884333422af8941c;

    /**
     * @dev Typehash constant for ERC-2612 (Permit)
     *
     * keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
     */
    bytes32 internal constant PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    /**
     * @dev Sets `value` as the allowance of `spender` over ``owner``'s tokens,
     * given ``owner``'s signed approval.
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `deadline` must be a timestamp in the future.
     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
     * over the EIP712-formatted function arguments.
     * - the signature must use ``owner``'s current nonce (see {nonces}).
     */
    function permit(
        address _owner, address _spender, uint256 _value, uint256 _deadline, uint8 _v, bytes32 _r, bytes32 _s
    ) external       override
{
        require(block.timestamp <= _deadline, "DEADLINE_EXPIRED");

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, _owner, _spender, _value, _useNonce(_owner), _deadline)
        );

        bytes32 hash = IEIP712StETH(getEIP712StETH()).hashTypedDataV4(address(this), structHash);

        require(SignatureUtils.isValidSignature(_owner, hash, _v, _r, _s), "INVALID_SIGNATURE");
        _approve(_owner, _spender, _value);
    }

    /**
     * @dev Returns the current nonce for `owner`. This value must be
     * included whenever a signature is generated for {permit}.
     *
     * Every successful call to {permit} increases ``owner``'s nonce by one. This
     * prevents a signature from being used multiple times.
     */
    function nonces(address owner) external view override returns (uint256) {
        return noncesByAddress[owner];
    }

    /**
     * @dev Returns the domain separator used in the encoding of the signature for {permit}, as defined by {EIP712}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return IEIP712StETH(getEIP712StETH()).domainSeparatorV4(address(this));
    }

    /**
     * @dev returns the fields and values that describe the domain separator used by this contract for EIP-712
     * signature.
     *
     * NB: compairing to the full-fledged ERC-5267 version:
     * - `salt` and `extensions` are unused
     * - `flags` is hex"0f" or 01111b
     *
     * @dev using shortened returns to reduce a bytecode size
     */
    function eip712Domain() external view returns (
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract
    ) {
        return IEIP712StETH(getEIP712StETH()).eip712Domain(address(this));
    }

    /**
     * @dev "Consume a nonce": return the current value and increment.
     */
    function _useNonce(address _owner) internal returns (uint256 current) {
        current = noncesByAddress[_owner];
        noncesByAddress[_owner] = current.add(1);
    }

    /**
     * @dev Initialize EIP712 message utils contract for stETH
     */
    function _initializeEIP712StETH(address _eip712StETH) internal {
        require(_eip712StETH != address(0), "ZERO_EIP712STETH");
        require(getEIP712StETH() == address(0), "EIP712STETH_ALREADY_SET");

        EIP712_STETH_POSITION.setStorageAddress(_eip712StETH);

        emit EIP712StETHInitialized(_eip712StETH);
    }

    /**
     * @dev Get EIP712 message utils contract
     */
    function getEIP712StETH() public view returns (address) {
        return EIP712_STETH_POSITION.getStorageAddress();
    }
}

interface IPostTokenRebaseReceiver {
    function handlePostTokenRebase(
        uint256 _reportTimestamp,
        uint256 _timeElapsed,
        uint256 _preTotalShares,
        uint256 _preTotalEther,
        uint256 _postTotalShares,
        uint256 _postTotalEther,
        uint256 _sharesMintedAsFees
    ) external;
}

interface IOracleReportSanityChecker {
    function checkAccountingOracleReport(
        uint256 _timeElapsed,
        uint256 _preCLBalance,
        uint256 _postCLBalance,
        uint256 _withdrawalVaultBalance,
        uint256 _elRewardsVaultBalance,
        uint256 _sharesRequestedToBurn,
        uint256 _preCLValidators,
        uint256 _postCLValidators
    ) external view;

    function smoothenTokenRebase(
        uint256 _preTotalPooledEther,
        uint256 _preTotalShares,
        uint256 _preCLBalance,
        uint256 _postCLBalance,
        uint256 _withdrawalVaultBalance,
        uint256 _elRewardsVaultBalance,
        uint256 _sharesRequestedToBurn,
        uint256 _etherToLockForWithdrawals,
        uint256 _newSharesToBurnForWithdrawals
    ) external view returns (
        uint256 withdrawals,
        uint256 elRewards,
        uint256 simulatedSharesToBurn,
        uint256 sharesToBurn
    );

    function checkWithdrawalQueueOracleReport(
        uint256 _lastFinalizableRequestId,
        uint256 _reportTimestamp
    ) external view;

    function checkSimulatedShareRate(
        uint256 _postTotalPooledEther,
        uint256 _postTotalShares,
        uint256 _etherLockedOnWithdrawalQueue,
        uint256 _sharesBurntDueToWithdrawals,
        uint256 _simulatedShareRate
    ) external view;
}

interface ILidoExecutionLayerRewardsVault {
    function withdrawRewards(uint256 _maxAmount) external returns (uint256 amount);
}

interface IWithdrawalVault {
    function withdrawWithdrawals(uint256 _amount) external;
}

interface IStakingRouter {
    function deposit(
        uint256 _depositsCount,
        uint256 _stakingModuleId,
        bytes memory _depositCalldata
    ) external payable;

    function getStakingRewardsDistribution()
        external
        view
        returns (
            address[] memory recipients,
            uint256[] memory stakingModuleIds,
            uint96[] memory stakingModuleFees,
            uint96 totalFee,
            uint256 precisionPoints
        );

    function getWithdrawalCredentials() external view returns (bytes32);

    function reportRewardsMinted(uint256[] memory _stakingModuleIds, uint256[] memory _totalShares) external;

    function getTotalFeeE4Precision() external view returns (uint16 totalFee);

    function getStakingFeeAggregateDistributionE4Precision() external view returns (
        uint16 modulesFee, uint16 treasuryFee
    );

    function getStakingModuleMaxDepositsCount(uint256 _stakingModuleId, uint256 _maxDepositsValue)
        external
        view
        returns (uint256);

    function TOTAL_BASIS_POINTS() external view returns (uint256);
}

interface IWithdrawalQueue {
    function prefinalize(uint256[] memory _batches, uint256 _maxShareRate)
        external
        view
        returns (uint256 ethToLock, uint256 sharesToBurn);

    function finalize(uint256 _lastIdToFinalize, uint256 _maxShareRate) external payable;

    function isPaused() external view returns (bool);

    function unfinalizedStETH() external view returns (uint256);

    function isBunkerModeActive() external view returns (bool);
}

/**
* @title Liquid staking pool implementation
*
* Lido is an Ethereum liquid staking protocol solving the problem of frozen staked ether on Consensus Layer
* being unavailable for transfers and DeFi on Execution Layer.
*
* Since balances of all token holders change when the amount of total pooled Ether
* changes, this token cannot fully implement ERC20 standard: it only emits `Transfer`
* events upon explicit transfer between holders. In contrast, when Lido oracle reports
* rewards, no Transfer events are generated: doing so would require emitting an event
* for each token holder and thus running an unbounded loop.
*
* ---
* NB: Order of inheritance must preserve the structured storage layout of the previous versions.
*
* @dev Lido is derived from `StETHPermit` that has a structured storage:
* SLOT 0: mapping (address => uint256) private shares (`StETH`)
* SLOT 1: mapping (address => mapping (address => uint256)) private allowances (`StETH`)
* SLOT 2: mapping(address => uint256) internal noncesByAddress (`StETHPermit`)
*
* `Versioned` and `AragonApp` both don't have the pre-allocated structured storage.
*/
// wake-disable-next-line
contract LidoMigrated is Versioned, StETHPermit, AragonApp {
    using SafeMath for uint256;
    using UnstructuredStorage for bytes32;
    using StakeLimitUnstructuredStorage for bytes32;
    using StakeLimitUtils for StakeLimitState.Data;

    /// ACL
    bytes32 public constant PAUSE_ROLE =
        0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d; // keccak256("PAUSE_ROLE");
    bytes32 public constant RESUME_ROLE =
        0x2fc10cc8ae19568712f7a176fb4978616a610650813c9d05326c34abb62749c7; // keccak256("RESUME_ROLE");
    bytes32 public constant STAKING_PAUSE_ROLE =
        0x84ea57490227bc2be925c684e2a367071d69890b629590198f4125a018eb1de8; // keccak256("STAKING_PAUSE_ROLE")
    bytes32 public constant STAKING_CONTROL_ROLE =
        0xa42eee1333c0758ba72be38e728b6dadb32ea767de5b4ddbaea1dae85b1b051f; // keccak256("STAKING_CONTROL_ROLE")
    bytes32 public constant UNSAFE_CHANGE_DEPOSITED_VALIDATORS_ROLE =
        0xe6dc5d79630c61871e99d341ad72c5a052bed2fc8c79e5a4480a7cd31117576c; // keccak256("UNSAFE_CHANGE_DEPOSITED_VALIDATORS_ROLE")

    uint256 private constant DEPOSIT_SIZE = 32 ether;

    /// @dev storage slot position for the Lido protocol contracts locator
    bytes32 internal constant LIDO_LOCATOR_POSITION =
        0x9ef78dff90f100ea94042bd00ccb978430524befc391d3e510b5f55ff3166df7; // keccak256("lido.Lido.lidoLocator")
    /// @dev storage slot position of the staking rate limit structure
    bytes32 internal constant STAKING_STATE_POSITION =
        0xa3678de4a579be090bed1177e0a24f77cc29d181ac22fd7688aca344d8938015; // keccak256("lido.Lido.stakeLimit");
    /// @dev amount of Ether (on the current Ethereum side) buffered on this smart contract balance
    bytes32 internal constant BUFFERED_ETHER_POSITION =
        0xed310af23f61f96daefbcd140b306c0bdbf8c178398299741687b90e794772b0; // keccak256("lido.Lido.bufferedEther");
    /// @dev number of deposited validators (incrementing counter of deposit operations).
    bytes32 internal constant DEPOSITED_VALIDATORS_POSITION =
        0xe6e35175eb53fc006520a2a9c3e9711a7c00de6ff2c32dd31df8c5a24cac1b5c; // keccak256("lido.Lido.depositedValidators");
    /// @dev total amount of ether on Consensus Layer (sum of all the balances of Lido validators)
    // "beacon" in the `keccak256()` parameter is staying here for compatibility reason
    bytes32 internal constant CL_BALANCE_POSITION =
        0xa66d35f054e68143c18f32c990ed5cb972bb68a68f500cd2dd3a16bbf3686483; // keccak256("lido.Lido.beaconBalance");
    /// @dev number of Lido's validators available in the Consensus Layer state
    // "beacon" in the `keccak256()` parameter is staying here for compatibility reason
    bytes32 internal constant CL_VALIDATORS_POSITION =
        0x9f70001d82b6ef54e9d3725b46581c3eb9ee3aa02b941b6aa54d678a9ca35b10; // keccak256("lido.Lido.beaconValidators");
    /// @dev Just a counter of total amount of execution layer rewards received by Lido contract. Not used in the logic.
    bytes32 internal constant TOTAL_EL_REWARDS_COLLECTED_POSITION =
        0xafe016039542d12eec0183bb0b1ffc2ca45b027126a494672fba4154ee77facb; // keccak256("lido.Lido.totalELRewardsCollected");

    // Staking was paused (don't accept user's ether submits)
    event StakingPaused();
    // Staking was resumed (accept user's ether submits)
    event StakingResumed();
    // Staking limit was set (rate limits user's submits)
    event StakingLimitSet(uint256 maxStakeLimit, uint256 stakeLimitIncreasePerBlock);
    // Staking limit was removed
    event StakingLimitRemoved();

    // Emits when validators number delivered by the oracle
    event CLValidatorsUpdated(
        uint256 indexed reportTimestamp,
        uint256 preCLValidators,
        uint256 postCLValidators
    );

    // Emits when var at `DEPOSITED_VALIDATORS_POSITION` changed
    event DepositedValidatorsChanged(
        uint256 depositedValidators
    );

    // Emits when oracle accounting report processed
    event ETHDistributed(
        uint256 indexed reportTimestamp,
        uint256 preCLBalance,
        uint256 postCLBalance,
        uint256 withdrawalsWithdrawn,
        uint256 executionLayerRewardsWithdrawn,
        uint256 postBufferedEther
    );

    // Emits when token rebased (total supply and/or total shares were changed)
    event TokenRebased(
        uint256 indexed reportTimestamp,
        uint256 timeElapsed,
        uint256 preTotalShares,
        uint256 preTotalEther,
        uint256 postTotalShares,
        uint256 postTotalEther,
        uint256 sharesMintedAsFees
    );

    // Lido locator set
    event LidoLocatorSet(address lidoLocator);

    // The amount of ETH withdrawn from LidoExecutionLayerRewardsVault to Lido
    event ELRewardsReceived(uint256 amount);

    // The amount of ETH withdrawn from WithdrawalVault to Lido
    event WithdrawalsReceived(uint256 amount);

    // Records a deposit made by a user
    event Submitted(address indexed sender, uint256 amount, address referral);

    // The `amount` of ether was sent to the deposit_contract.deposit function
    event Unbuffered(uint256 amount);

    /**
    * @dev As AragonApp, Lido contract must be initialized with following variables:
    *      NB: by default, staking and the whole Lido pool are in paused state
    *
    * The contract's balance must be non-zero to allow initial holder bootstrap.
    *
    * @param _lidoLocator lido locator contract
    * @param _eip712StETH eip712 helper contract for StETH
    */
    function initialize(address _lidoLocator, address _eip712StETH)
        public
        payable
        onlyInit
    {
        _bootstrapInitialHolder();
        _initialize_v2(_lidoLocator, _eip712StETH);
        initialized();
    }

    /**
     * initializer for the Lido version "2"
     */
    function _initialize_v2(address _lidoLocator, address _eip712StETH) internal {
        _setContractVersion(2);

        LIDO_LOCATOR_POSITION.setStorageAddress(_lidoLocator);
        _initializeEIP712StETH(_eip712StETH);

        // set infinite allowance for burner from withdrawal queue
        // to burn finalized requests' shares
        _approve(
            ILidoLocator(_lidoLocator).withdrawalQueue(),
            ILidoLocator(_lidoLocator).burner(),
            INFINITE_ALLOWANCE
        );

        emit LidoLocatorSet(_lidoLocator);
    }

    /**
     * @notice A function to finalize upgrade to v2 (from v1). Can be called only once
     * @dev Value "1" in CONTRACT_VERSION_POSITION is skipped due to change in numbering
     *
     * The initial protocol token holder must exist.
     *
     * For more details see https://github.com/lidofinance/lido-improvement-proposals/blob/develop/LIPS/lip-10.md
     */
    function finalizeUpgrade_v2(address _lidoLocator, address _eip712StETH) external {
        _checkContractVersion(0);
        require(hasInitialized(), "NOT_INITIALIZED");

        require(_lidoLocator != address(0), "LIDO_LOCATOR_ZERO_ADDRESS");
        require(_eip712StETH != address(0), "EIP712_STETH_ZERO_ADDRESS");

        require(_sharesOf(INITIAL_TOKEN_HOLDER) != 0, "INITIAL_HOLDER_EXISTS");

        _initialize_v2(_lidoLocator, _eip712StETH);
    }

    /**
     * @notice Stops accepting new Ether to the protocol
     *
     * @dev While accepting new Ether is stopped, calls to the `submit` function,
     * as well as to the default payable function, will revert.
     *
     * Emits `StakingPaused` event.
     */
    function pauseStaking() external {
        _auth(STAKING_PAUSE_ROLE);

        _pauseStaking();
    }

    /**
     * @notice Resumes accepting new Ether to the protocol (if `pauseStaking` was called previously)
     * NB: Staking could be rate-limited by imposing a limit on the stake amount
     * at each moment in time, see `setStakingLimit()` and `removeStakingLimit()`
     *
     * @dev Preserves staking limit if it was set previously
     *
     * Emits `StakingResumed` event
     */
    function resumeStaking() external {
        _auth(STAKING_CONTROL_ROLE);
        require(hasInitialized(), "NOT_INITIALIZED");

        _resumeStaking();
    }

    /**
     * @notice Sets the staking rate limit
     *
     * ▲ Stake limit
     * │.....  .....   ........ ...            ....     ... Stake limit = max
     * │      .       .        .   .   .      .    . . .
     * │     .       .              . .  . . .      . .
     * │            .                .  . . .
     * │──────────────────────────────────────────────────> Time
     * │     ^      ^          ^   ^^^  ^ ^ ^     ^^^ ^     Stake events
     *
     * @dev Reverts if:
     * - `_maxStakeLimit` == 0
     * - `_maxStakeLimit` >= 2^96
     * - `_maxStakeLimit` < `_stakeLimitIncreasePerBlock`
     * - `_maxStakeLimit` / `_stakeLimitIncreasePerBlock` >= 2^32 (only if `_stakeLimitIncreasePerBlock` != 0)
     *
     * Emits `StakingLimitSet` event
     *
     * @param _maxStakeLimit max stake limit value
     * @param _stakeLimitIncreasePerBlock stake limit increase per single block
     */
    function setStakingLimit(uint256 _maxStakeLimit, uint256 _stakeLimitIncreasePerBlock) external {
        _auth(STAKING_CONTROL_ROLE);

        STAKING_STATE_POSITION.setStorageStakeLimitStruct(
            STAKING_STATE_POSITION.getStorageStakeLimitStruct().setStakingLimit(_maxStakeLimit, _stakeLimitIncreasePerBlock)
        );

        emit StakingLimitSet(_maxStakeLimit, _stakeLimitIncreasePerBlock);
    }

    /**
     * @notice Removes the staking rate limit
     *
     * Emits `StakingLimitRemoved` event
     */
    function removeStakingLimit() external {
        _auth(STAKING_CONTROL_ROLE);

        STAKING_STATE_POSITION.setStorageStakeLimitStruct(STAKING_STATE_POSITION.getStorageStakeLimitStruct().removeStakingLimit());

        emit StakingLimitRemoved();
    }

    /**
     * @notice Check staking state: whether it's paused or not
     */
    function isStakingPaused() external view returns (bool) {
        return STAKING_STATE_POSITION.getStorageStakeLimitStruct().isStakingPaused();
    }


    /**
     * @notice Returns how much Ether can be staked in the current block
     * @dev Special return values:
     * - 2^256 - 1 if staking is unlimited;
     * - 0 if staking is paused or if limit is exhausted.
     */
    function getCurrentStakeLimit() external view returns (uint256) {
        return _getCurrentStakeLimit(STAKING_STATE_POSITION.getStorageStakeLimitStruct());
    }

    /**
     * @notice Returns full info about current stake limit params and state
     * @dev Might be used for the advanced integration requests.
     * @return isStakingPaused staking pause state (equivalent to return of isStakingPaused())
     * @return isStakingLimitSet whether the stake limit is set
     * @return currentStakeLimit current stake limit (equivalent to return of getCurrentStakeLimit())
     * @return maxStakeLimit max stake limit
     * @return maxStakeLimitGrowthBlocks blocks needed to restore max stake limit from the fully exhausted state
     * @return prevStakeLimit previously reached stake limit
     * @return prevStakeBlockNumber previously seen block number
     */
    function getStakeLimitFullInfo()
        external
        view
        returns (
            bool isStakingPaused,
            bool isStakingLimitSet,
            uint256 currentStakeLimit,
            uint256 maxStakeLimit,
            uint256 maxStakeLimitGrowthBlocks,
            uint256 prevStakeLimit,
            uint256 prevStakeBlockNumber
        )
    {
        StakeLimitState.Data memory stakeLimitData = STAKING_STATE_POSITION.getStorageStakeLimitStruct();

        isStakingPaused = stakeLimitData.isStakingPaused();
        isStakingLimitSet = stakeLimitData.isStakingLimitSet();

        currentStakeLimit = _getCurrentStakeLimit(stakeLimitData);

        maxStakeLimit = stakeLimitData.maxStakeLimit;
        maxStakeLimitGrowthBlocks = stakeLimitData.maxStakeLimitGrowthBlocks;
        prevStakeLimit = stakeLimitData.prevStakeLimit;
        prevStakeBlockNumber = stakeLimitData.prevStakeBlockNumber;
    }

    /**
    * @notice Send funds to the pool
    * @dev Users are able to submit their funds by transacting to the fallback function.
    * Unlike vanilla Ethereum Deposit contract, accepting only 32-Ether transactions, Lido
    * accepts payments of any size. Submitted Ethers are stored in Buffer until someone calls
    * deposit() and pushes them to the Ethereum Deposit contract.
    */
    // solhint-disable-next-line no-complex-fallback
    fallback() external payable {
        // protection against accidental submissions by calling non-existent function
        require(msg.data.length == 0, "NON_EMPTY_DATA");
        _submit(address(0));
    }

    /**
     * @notice Send funds to the pool with optional _referral parameter
     * @dev This function is alternative way to submit funds. Supports optional referral address.
     * @return Amount of StETH shares generated
     */
    function submit(address _referral) external payable returns (uint256) {
        return _submit(_referral);
    }

    /**
     * @notice A payable function for execution layer rewards. Can be called only by `ExecutionLayerRewardsVault`
     * @dev We need a dedicated function because funds received by the default payable function
     * are treated as a user deposit
     */
    function receiveELRewards() external payable {
        require(msg.sender == getLidoLocator().elRewardsVault());

        TOTAL_EL_REWARDS_COLLECTED_POSITION.setStorageUint256(getTotalELRewardsCollected().add(msg.value));

        emit ELRewardsReceived(msg.value);
    }

    /**
    * @notice A payable function for withdrawals acquisition. Can be called only by `WithdrawalVault`
    * @dev We need a dedicated function because funds received by the default payable function
    * are treated as a user deposit
    */
    function receiveWithdrawals() external payable {
        require(msg.sender == getLidoLocator().withdrawalVault());

        emit WithdrawalsReceived(msg.value);
    }

    /**
     * @notice Stop pool routine operations
     */
    function stop() external {
        _auth(PAUSE_ROLE);

        _stop();
        _pauseStaking();
    }

    /**
     * @notice Resume pool routine operations
     * @dev Staking is resumed after this call using the previously set limits (if any)
     */
    function resume() external {
        _auth(RESUME_ROLE);

        _resume();
        _resumeStaking();
    }

    /**
     * The structure is used to aggregate the `handleOracleReport` provided data.
     * @dev Using the in-memory structure addresses `stack too deep` issues.
     */
    struct OracleReportedData {
        // Oracle timings
        uint256 reportTimestamp;
        uint256 timeElapsed;
        // CL values
        uint256 clValidators;
        uint256 postCLBalance;
        // EL values
        uint256 withdrawalVaultBalance;
        uint256 elRewardsVaultBalance;
        uint256 sharesRequestedToBurn;
        // Decision about withdrawals processing
        uint256[] withdrawalFinalizationBatches;
        uint256 simulatedShareRate;
    }

    /**
     * The structure is used to preload the contract using `getLidoLocator()` via single call
     */
    struct OracleReportContracts {
        address accountingOracle;
        address elRewardsVault;
        address oracleReportSanityChecker;
        address burner;
        address withdrawalQueue;
        address withdrawalVault;
        address postTokenRebaseReceiver;
    }

    function handleOracleReport(
        // Oracle timings
        uint256 _reportTimestamp,
        uint256 _timeElapsed,
        // CL values
        uint256 _clValidators,
        uint256 _clBalance,
        // EL values
        uint256 _withdrawalVaultBalance,
        uint256 _elRewardsVaultBalance,
        uint256 _sharesRequestedToBurn,
        // Decision about withdrawals processing
        uint256[] memory _withdrawalFinalizationBatches,
        uint256 _simulatedShareRate
    ) external returns (uint256[4] memory postRebaseAmounts) {
        _whenNotStopped();

        return _handleOracleReport(
            OracleReportedData(
                _reportTimestamp,
                _timeElapsed,
                _clValidators,
                _clBalance,
                _withdrawalVaultBalance,
                _elRewardsVaultBalance,
                _sharesRequestedToBurn,
                _withdrawalFinalizationBatches,
                _simulatedShareRate
            )
        );
    }

    /**
     * @notice Unsafely change deposited validators
     *
     * The method unsafely changes deposited validator counter.
     * Can be required when onboarding external validators to Lido
     * (i.e., had deposited before and rotated their type-0x00 withdrawal credentials to Lido)
     *
     * @param _newDepositedValidators new value
     */
    function unsafeChangeDepositedValidators(uint256 _newDepositedValidators) external {
        _auth(UNSAFE_CHANGE_DEPOSITED_VALIDATORS_ROLE);

        DEPOSITED_VALIDATORS_POSITION.setStorageUint256(_newDepositedValidators);

        emit DepositedValidatorsChanged(_newDepositedValidators);
    }

    /**
     * @notice Overrides default AragonApp behaviour to disallow recovery.
     */
    function transferToVault(address /* _token */) external override {
        revert("NOT_SUPPORTED");
    }

    /**
    * @notice Get the amount of Ether temporary buffered on this contract balance
    * @dev Buffered balance is kept on the contract from the moment the funds are received from user
    * until the moment they are actually sent to the official Deposit contract.
    * @return amount of buffered funds in wei
    */
    function getBufferedEther() external view returns (uint256) {
        return _getBufferedEther();
    }

    /**
     * @notice Get total amount of execution layer rewards collected to Lido contract
     * @dev Ether got through LidoExecutionLayerRewardsVault is kept on this contract's balance the same way
     * as other buffered Ether is kept (until it gets deposited)
     * @return amount of funds received as execution layer rewards in wei
     */
    function getTotalELRewardsCollected() public view returns (uint256) {
        return TOTAL_EL_REWARDS_COLLECTED_POSITION.getStorageUint256();
    }

    /**
     * @notice Gets authorized oracle address
     * @return address of oracle contract
     */
    function getLidoLocator() public view returns (ILidoLocator) {
        return ILidoLocator(LIDO_LOCATOR_POSITION.getStorageAddress());
    }

    /**
    * @notice Returns the key values related to Consensus Layer side of the contract. It historically contains beacon
    * @return depositedValidators - number of deposited validators from Lido contract side
    * @return beaconValidators - number of Lido validators visible on Consensus Layer, reported by oracle
    * @return beaconBalance - total amount of ether on the Consensus Layer side (sum of all the balances of Lido validators)
    *
    * @dev `beacon` in naming still here for historical reasons
    */
    function getBeaconStat() external view returns (uint256 depositedValidators, uint256 beaconValidators, uint256 beaconBalance) {
        depositedValidators = DEPOSITED_VALIDATORS_POSITION.getStorageUint256();
        beaconValidators = CL_VALIDATORS_POSITION.getStorageUint256();
        beaconBalance = CL_BALANCE_POSITION.getStorageUint256();
    }

    /**
     * @dev Check that Lido allows depositing buffered ether to the consensus layer
     * Depends on the bunker state and protocol's pause state
     */
    function canDeposit() public view returns (bool) {
        return !_withdrawalQueue().isBunkerModeActive() && !isStopped();
    }

    /**
     * @dev Returns depositable ether amount.
     * Takes into account unfinalized stETH required by WithdrawalQueue
     */
    function getDepositableEther() public view returns (uint256) {
        uint256 bufferedEther = _getBufferedEther();
        uint256 withdrawalReserve = _withdrawalQueue().unfinalizedStETH();
        return bufferedEther > withdrawalReserve ? bufferedEther - withdrawalReserve : 0;
    }

    /**
     * @dev Invokes a deposit call to the Staking Router contract and updates buffered counters
     * @param _maxDepositsCount max deposits count
     * @param _stakingModuleId id of the staking module to be deposited
     * @param _depositCalldata module calldata
     */
    function deposit(uint256 _maxDepositsCount, uint256 _stakingModuleId, bytes memory _depositCalldata) external {
        ILidoLocator locator = getLidoLocator();

        require(msg.sender == locator.depositSecurityModule(), "APP_AUTH_DSM_FAILED");
        require(canDeposit(), "CAN_NOT_DEPOSIT");

        IStakingRouter stakingRouter = _stakingRouter();
        uint256 depositsCount = Math256.min(
            _maxDepositsCount,
            stakingRouter.getStakingModuleMaxDepositsCount(_stakingModuleId, getDepositableEther())
        );

        uint256 depositsValue;
        if (depositsCount > 0) {
            depositsValue = depositsCount.mul(DEPOSIT_SIZE);
            /// @dev firstly update the local state of the contract to prevent a reentrancy attack,
            ///     even if the StakingRouter is a trusted contract.
            BUFFERED_ETHER_POSITION.setStorageUint256(_getBufferedEther().sub(depositsValue));
            emit Unbuffered(depositsValue);

            uint256 newDepositedValidators = DEPOSITED_VALIDATORS_POSITION.getStorageUint256().add(depositsCount);
            DEPOSITED_VALIDATORS_POSITION.setStorageUint256(newDepositedValidators);
            emit DepositedValidatorsChanged(newDepositedValidators);
        }

        /// @dev transfer ether to StakingRouter and make a deposit at the same time. All the ether
        ///     sent to StakingRouter is counted as deposited. If StakingRouter can't deposit all
        ///     passed ether it MUST revert the whole transaction (never happens in normal circumstances)
        stakingRouter.deposit.value(depositsValue)(depositsCount, _stakingModuleId, _depositCalldata);
    }

    /// DEPRECATED PUBLIC METHODS

    /**
     * @notice Returns current withdrawal credentials of deposited validators
     * @dev DEPRECATED: use StakingRouter.getWithdrawalCredentials() instead
     */
    function getWithdrawalCredentials() external view returns (bytes32) {
        return _stakingRouter().getWithdrawalCredentials();
    }

    /**
     * @notice Returns legacy oracle
     * @dev DEPRECATED: the `AccountingOracle` superseded the old one
     */
    function getOracle() external view returns (address) {
        return getLidoLocator().legacyOracle();
    }

    /**
     * @notice Returns the treasury address
     * @dev DEPRECATED: use LidoLocator.treasury()
     */
    function getTreasury() external view returns (address) {
        return _treasury();
    }

    /**
     * @notice Returns current staking rewards fee rate
     * @dev DEPRECATED: Now fees information is stored in StakingRouter and
     * with higher precision. Use StakingRouter.getStakingFeeAggregateDistribution() instead.
     * @return totalFee total rewards fee in 1e4 precision (10000 is 100%). The value might be
     * inaccurate because the actual value is truncated here to 1e4 precision.
     */
    function getFee() external view returns (uint16 totalFee) {
        totalFee = _stakingRouter().getTotalFeeE4Precision();
    }

    /**
     * @notice Returns current fee distribution, values relative to the total fee (getFee())
     * @dev DEPRECATED: Now fees information is stored in StakingRouter and
     * with higher precision. Use StakingRouter.getStakingFeeAggregateDistribution() instead.
     * @return treasuryFeeBasisPoints return treasury fee in TOTAL_BASIS_POINTS (10000 is 100% fee) precision
     * @return insuranceFeeBasisPoints always returns 0 because the capability to send fees to
     * insurance from Lido contract is removed.
     * @return operatorsFeeBasisPoints return total fee for all operators of all staking modules in
     * TOTAL_BASIS_POINTS (10000 is 100% fee) precision.
     * Previously returned total fee of all node operators of NodeOperatorsRegistry (Curated staking module now)
     * The value might be inaccurate because the actual value is truncated here to 1e4 precision.
     */
    function getFeeDistribution()
        external view
        returns (
            uint16 treasuryFeeBasisPoints,
            uint16 insuranceFeeBasisPoints,
            uint16 operatorsFeeBasisPoints
        )
    {
        IStakingRouter stakingRouter = _stakingRouter();
        uint256 totalBasisPoints = stakingRouter.TOTAL_BASIS_POINTS();
        uint256 totalFee = stakingRouter.getTotalFeeE4Precision();
        (uint256 treasuryFeeBasisPointsAbs, uint256 operatorsFeeBasisPointsAbs) = stakingRouter
            .getStakingFeeAggregateDistributionE4Precision();

        insuranceFeeBasisPoints = 0;  // explicitly set to zero
        treasuryFeeBasisPoints = uint16((treasuryFeeBasisPointsAbs * totalBasisPoints) / totalFee);
        operatorsFeeBasisPoints = uint16((operatorsFeeBasisPointsAbs * totalBasisPoints) / totalFee);
    }

    /*
     * @dev updates Consensus Layer state snapshot according to the current report
     *
     * NB: conventions and assumptions
     *
     * `depositedValidators` are total amount of the **ever** deposited Lido validators
     * `_postClValidators` are total amount of the **ever** appeared on the CL side Lido validators
     *
     * i.e., exited Lido validators persist in the state, just with a different status
     */
    function _processClStateUpdate(
        uint256 _reportTimestamp,
        uint256 _preClValidators,
        uint256 _postClValidators,
        uint256 _postClBalance
    ) internal returns (uint256 preCLBalance) {
        uint256 depositedValidators = DEPOSITED_VALIDATORS_POSITION.getStorageUint256();
        require(_postClValidators <= depositedValidators, "REPORTED_MORE_DEPOSITED");
        require(_postClValidators >= _preClValidators, "REPORTED_LESS_VALIDATORS");

        if (_postClValidators > _preClValidators) {
            CL_VALIDATORS_POSITION.setStorageUint256(_postClValidators);
        }

        uint256 appearedValidators = _postClValidators - _preClValidators;
        preCLBalance = CL_BALANCE_POSITION.getStorageUint256();
        // Take into account the balance of the newly appeared validators
        preCLBalance = preCLBalance.add(appearedValidators.mul(DEPOSIT_SIZE));

        // Save the current CL balance and validators to
        // calculate rewards on the next push
        CL_BALANCE_POSITION.setStorageUint256(_postClBalance);

        emit CLValidatorsUpdated(_reportTimestamp, _preClValidators, _postClValidators);
    }

    /**
     * @dev collect ETH from ELRewardsVault and WithdrawalVault, then send to WithdrawalQueue
     */
    function _collectRewardsAndProcessWithdrawals(
        OracleReportContracts memory _contracts,
        uint256 _withdrawalsToWithdraw,
        uint256 _elRewardsToWithdraw,
        uint256[] memory _withdrawalFinalizationBatches,
        uint256 _simulatedShareRate,
        uint256 _etherToLockOnWithdrawalQueue
    ) internal {
        // withdraw execution layer rewards and put them to the buffer
        if (_elRewardsToWithdraw > 0) {
            ILidoExecutionLayerRewardsVault(_contracts.elRewardsVault).withdrawRewards(_elRewardsToWithdraw);
        }

        // withdraw withdrawals and put them to the buffer
        if (_withdrawalsToWithdraw > 0) {
            IWithdrawalVault(_contracts.withdrawalVault).withdrawWithdrawals(_withdrawalsToWithdraw);
        }

        // finalize withdrawals (send ether, assign shares for burning)
        if (_etherToLockOnWithdrawalQueue > 0) {
            IWithdrawalQueue withdrawalQueue = IWithdrawalQueue(_contracts.withdrawalQueue);
            withdrawalQueue.finalize.value(_etherToLockOnWithdrawalQueue)(
                _withdrawalFinalizationBatches[_withdrawalFinalizationBatches.length - 1],
                _simulatedShareRate
            );
        }

        uint256 postBufferedEther = _getBufferedEther()
            .add(_elRewardsToWithdraw) // Collected from ELVault
            .add(_withdrawalsToWithdraw) // Collected from WithdrawalVault
            .sub(_etherToLockOnWithdrawalQueue); // Sent to WithdrawalQueue

        _setBufferedEther(postBufferedEther);
    }

    /**
     * @dev return amount to lock on withdrawal queue and shares to burn
     * depending on the finalization batch parameters
     */
    function _calculateWithdrawals(
        OracleReportContracts memory _contracts,
        OracleReportedData memory _reportedData
    ) internal view returns (
        uint256 etherToLock, uint256 sharesToBurn
    ) {
        IWithdrawalQueue withdrawalQueue = IWithdrawalQueue(_contracts.withdrawalQueue);

        if (!withdrawalQueue.isPaused()) {
            IOracleReportSanityChecker(_contracts.oracleReportSanityChecker).checkWithdrawalQueueOracleReport(
                _reportedData.withdrawalFinalizationBatches[_reportedData.withdrawalFinalizationBatches.length - 1],
                _reportedData.reportTimestamp
            );

            (etherToLock, sharesToBurn) = withdrawalQueue.prefinalize(
                _reportedData.withdrawalFinalizationBatches,
                _reportedData.simulatedShareRate
            );
        }
    }

    /**
     * @dev calculate the amount of rewards and distribute it
     */
    function _processRewards(
        OracleReportContext memory _reportContext,
        uint256 _postCLBalance,
        uint256 _withdrawnWithdrawals,
        uint256 _withdrawnElRewards
    ) internal returns (uint256 sharesMintedAsFees) {
        uint256 postCLTotalBalance = _postCLBalance.add(_withdrawnWithdrawals);
        // Don’t mint/distribute any protocol fee on the non-profitable Lido oracle report
        // (when consensus layer balance delta is zero or negative).
        // See LIP-12 for details:
        // https://research.lido.fi/t/lip-12-on-chain-part-of-the-rewards-distribution-after-the-merge/1625
        if (postCLTotalBalance > _reportContext.preCLBalance) {
            uint256 consensusLayerRewards = postCLTotalBalance - _reportContext.preCLBalance;

            console.log("total_reward", consensusLayerRewards.add(_withdrawnElRewards));
            sharesMintedAsFees = _distributeFee(
                _reportContext.preTotalPooledEther,
                _reportContext.preTotalShares,
                consensusLayerRewards.add(_withdrawnElRewards)
            );
        }
    }

    /**
     * @dev Process user deposit, mints liquid tokens and increase the pool buffer
     * @param _referral address of referral.
     * @return amount of StETH shares generated
     */
    function _submit(address _referral) internal returns (uint256) {
        require(msg.value != 0, "ZERO_DEPOSIT");

        StakeLimitState.Data memory stakeLimitData = STAKING_STATE_POSITION.getStorageStakeLimitStruct();
        // There is an invariant that protocol pause also implies staking pause.
        // Thus, no need to check protocol pause explicitly.
        require(!stakeLimitData.isStakingPaused(), "STAKING_PAUSED");

        if (stakeLimitData.isStakingLimitSet()) {
            uint256 currentStakeLimit = stakeLimitData.calculateCurrentStakeLimit();

            require(msg.value <= currentStakeLimit, "STAKE_LIMIT");

            STAKING_STATE_POSITION.setStorageStakeLimitStruct(stakeLimitData.updatePrevStakeLimit(currentStakeLimit - msg.value));
        }

        uint256 sharesAmount = getSharesByPooledEth(msg.value);

        _mintShares(msg.sender, sharesAmount);

        _setBufferedEther(_getBufferedEther().add(msg.value));
        emit Submitted(msg.sender, msg.value, _referral);

        _emitTransferAfterMintingShares(msg.sender, sharesAmount);
        return sharesAmount;
    }

    /**
     * @dev Staking router rewards distribution.
     *
     * Corresponds to the return value of `IStakingRouter.newTotalPooledEtherForRewards()`
     * Prevents `stack too deep` issue.
     */
    struct StakingRewardsDistribution {
        address[] recipients;
        uint256[] moduleIds;
        uint96[] modulesFees;
        uint96 totalFee;
        uint256 precisionPoints;
    }

    /**
     * @dev Get staking rewards distribution from staking router.
     */
    function _getStakingRewardsDistribution() internal view returns (
        StakingRewardsDistribution memory ret,
        IStakingRouter router
    ) {
        router = _stakingRouter();

        (
            ret.recipients,
            ret.moduleIds,
            ret.modulesFees,
            ret.totalFee,
            ret.precisionPoints
        ) = router.getStakingRewardsDistribution();

        require(ret.recipients.length == ret.modulesFees.length, "WRONG_RECIPIENTS_INPUT");
        require(ret.moduleIds.length == ret.modulesFees.length, "WRONG_MODULE_IDS_INPUT");
    }

    /**
     * @dev Distributes fee portion of the rewards by minting and distributing corresponding amount of liquid tokens.
     * @param _preTotalPooledEther Total supply before report-induced changes applied
     * @param _preTotalShares Total shares before report-induced changes applied
     * @param _totalRewards Total rewards accrued both on the Execution Layer and the Consensus Layer sides in wei.
     */
    function _distributeFee(
        uint256 _preTotalPooledEther,
        uint256 _preTotalShares,
        uint256 _totalRewards
    ) internal returns (uint256 sharesMintedAsFees) {
        // We need to take a defined percentage of the reported reward as a fee, and we do
        // this by minting new token shares and assigning them to the fee recipients (see
        // StETH docs for the explanation of the shares mechanics). The staking rewards fee
        // is defined in basis points (1 basis point is equal to 0.01%, 10000 (TOTAL_BASIS_POINTS) is 100%).
        //
        // Since we are increasing totalPooledEther by _totalRewards (totalPooledEtherWithRewards),
        // the combined cost of all holders' shares has became _totalRewards StETH tokens more,
        // effectively splitting the reward between each token holder proportionally to their token share.
        //
        // Now we want to mint new shares to the fee recipient, so that the total cost of the
        // newly-minted shares exactly corresponds to the fee taken:
        //
        // totalPooledEtherWithRewards = _preTotalPooledEther + _totalRewards
        // shares2mint * newShareCost = (_totalRewards * totalFee) / PRECISION_POINTS
        // newShareCost = totalPooledEtherWithRewards / (_preTotalShares + shares2mint)
        //
        // which follows to:
        //
        //                        _totalRewards * totalFee * _preTotalShares
        // shares2mint = --------------------------------------------------------------
        //                 (totalPooledEtherWithRewards * PRECISION_POINTS) - (_totalRewards * totalFee)
        //
        // The effect is that the given percentage of the reward goes to the fee recipient, and
        // the rest of the reward is distributed between token holders proportionally to their
        // token shares.

        (
            StakingRewardsDistribution memory rewardsDistribution,
            IStakingRouter router
        ) = _getStakingRewardsDistribution();

        if (rewardsDistribution.totalFee > 0) {
            uint256 totalPooledEtherWithRewards = _preTotalPooledEther.add(_totalRewards);

            sharesMintedAsFees =
                _totalRewards.mul(rewardsDistribution.totalFee).mul(_preTotalShares).div(
                    totalPooledEtherWithRewards.mul(
                        rewardsDistribution.precisionPoints
                    ).sub(_totalRewards.mul(rewardsDistribution.totalFee))
                );

            console.log("sharesMintedAsFees", sharesMintedAsFees);
            _mintShares(address(this), sharesMintedAsFees);

            (uint256[] memory moduleRewards, uint256 totalModuleRewards) =
                _transferModuleRewards(
                    rewardsDistribution.recipients,
                    rewardsDistribution.modulesFees,
                    rewardsDistribution.totalFee,
                    sharesMintedAsFees
                );

            _transferTreasuryRewards(sharesMintedAsFees.sub(totalModuleRewards));

            router.reportRewardsMinted(
                rewardsDistribution.moduleIds,
                moduleRewards
            );
        }
    }

    function _transferModuleRewards(
        address[] memory recipients,
        uint96[] memory modulesFees,
        uint256 totalFee,
        uint256 totalRewards
    ) internal returns (uint256[] memory moduleRewards, uint256 totalModuleRewards) {
        moduleRewards = new uint256[](recipients.length);

        for (uint256 i; i < recipients.length; ++i) {
            if (modulesFees[i] > 0) {
                uint256 iModuleRewards = totalRewards.mul(modulesFees[i]).div(totalFee);
                moduleRewards[i] = iModuleRewards;
                _transferShares(address(this), recipients[i], iModuleRewards);
                _emitTransferAfterMintingShares(recipients[i], iModuleRewards);
                totalModuleRewards = totalModuleRewards.add(iModuleRewards);
            }
        }
    }

    function _transferTreasuryRewards(uint256 treasuryReward) internal {
        address treasury = _treasury();
        _transferShares(address(this), treasury, treasuryReward);
        _emitTransferAfterMintingShares(treasury, treasuryReward);
    }

    /**
     * @dev Gets the amount of Ether temporary buffered on this contract balance
     */
    function _getBufferedEther() internal view returns (uint256) {
        return BUFFERED_ETHER_POSITION.getStorageUint256();
    }

    function _setBufferedEther(uint256 _newBufferedEther) internal {
        BUFFERED_ETHER_POSITION.setStorageUint256(_newBufferedEther);
    }

    /// @dev Calculates and returns the total base balance (multiple of 32) of validators in transient state,
    ///     i.e. submitted to the official Deposit contract but not yet visible in the CL state.
    /// @return transient balance in wei (1e-18 Ether)
    function _getTransientBalance() internal view returns (uint256) {
        uint256 depositedValidators = DEPOSITED_VALIDATORS_POSITION.getStorageUint256();
        uint256 clValidators = CL_VALIDATORS_POSITION.getStorageUint256();
        // clValidators can never be less than deposited ones.
        assert(depositedValidators >= clValidators);
        return (depositedValidators - clValidators).mul(DEPOSIT_SIZE);
    }

    /**
     * @dev Gets the total amount of Ether controlled by the system
     * @return total balance in wei
     */
    function _getTotalPooledEther() internal view override returns (uint256) {
        return _getBufferedEther()
            .add(CL_BALANCE_POSITION.getStorageUint256())
            .add(_getTransientBalance());
    }

    function _pauseStaking() internal {
        STAKING_STATE_POSITION.setStorageStakeLimitStruct(
            STAKING_STATE_POSITION.getStorageStakeLimitStruct().setStakeLimitPauseState(true)
        );

        emit StakingPaused();
    }

    function _resumeStaking() internal {
        STAKING_STATE_POSITION.setStorageStakeLimitStruct(
            STAKING_STATE_POSITION.getStorageStakeLimitStruct().setStakeLimitPauseState(false)
        );

        emit StakingResumed();
    }

    function _getCurrentStakeLimit(StakeLimitState.Data memory _stakeLimitData) internal view returns (uint256) {
        if (_stakeLimitData.isStakingPaused()) {
            return 0;
        }
        if (!_stakeLimitData.isStakingLimitSet()) {
            return uint256(-1);
        }

        return _stakeLimitData.calculateCurrentStakeLimit();
    }

    /**
     * @dev Size-efficient analog of the `auth(_role)` modifier
     * @param _role Permission name
     */
    function _auth(bytes32 _role) internal view {
        require(canPerform(msg.sender, _role, new uint256[](0)), "APP_AUTH_FAILED");
    }

    /**
     * @dev Intermediate data structure for `_handleOracleReport`
     * Helps to overcome `stack too deep` issue.
     */
    struct OracleReportContext {
        uint256 preCLValidators;
        uint256 preCLBalance;
        uint256 preTotalPooledEther;
        uint256 preTotalShares;
        uint256 etherToLockOnWithdrawalQueue;
        uint256 sharesToBurnFromWithdrawalQueue;
        uint256 simulatedSharesToBurn;
        uint256 sharesToBurn;
        uint256 sharesMintedAsFees;
    }

    /**
     * @dev Handle oracle report method operating with the data-packed structs
     * Using structs helps to overcome 'stack too deep' issue.
     *
     * The method updates the protocol's accounting state.
     * Key steps:
     * 1. Take a snapshot of the current (pre-) state
     * 2. Pass the report data to sanity checker (reverts if malformed)
     * 3. Pre-calculate the ether to lock for withdrawal queue and shares to be burnt
     * 4. Pass the accounting values to sanity checker to smoothen positive token rebase
     *    (i.e., postpone the extra rewards to be applied during the next rounds)
     * 5. Invoke finalization of the withdrawal requests
     * 6. Burn excess shares within the allowed limit (can postpone some shares to be burnt later)
     * 7. Distribute protocol fee (treasury & node operators)
     * 8. Complete token rebase by informing observers (emit an event and call the external receivers if any)
     * 9. Sanity check for the provided simulated share rate
     */
    function _handleOracleReport(OracleReportedData memory _reportedData) internal returns (uint256[4] memory) {
        OracleReportContracts memory contracts = _loadOracleReportContracts();

        require(msg.sender == contracts.accountingOracle, "APP_AUTH_FAILED");
        require(_reportedData.reportTimestamp <= block.timestamp, "INVALID_REPORT_TIMESTAMP");

        OracleReportContext memory reportContext;

        // Step 1.
        // Take a snapshot of the current (pre-) state
        reportContext.preTotalPooledEther = _getTotalPooledEther();
        reportContext.preTotalShares = _getTotalShares();
        reportContext.preCLValidators = CL_VALIDATORS_POSITION.getStorageUint256();
        reportContext.preCLBalance = _processClStateUpdate(
            _reportedData.reportTimestamp,
            reportContext.preCLValidators,
            _reportedData.clValidators,
            _reportedData.postCLBalance
        );

        // Step 2.
        // Pass the report data to sanity checker (reverts if malformed)
        _checkAccountingOracleReport(contracts, _reportedData, reportContext);

        // Step 3.
        // Pre-calculate the ether to lock for withdrawal queue and shares to be burnt
        // due to withdrawal requests to finalize
        if (_reportedData.withdrawalFinalizationBatches.length != 0) {
            (
                reportContext.etherToLockOnWithdrawalQueue,
                reportContext.sharesToBurnFromWithdrawalQueue
            ) = _calculateWithdrawals(contracts, _reportedData);

            if (reportContext.sharesToBurnFromWithdrawalQueue > 0) {
                IBurner(contracts.burner).requestBurnShares(
                    contracts.withdrawalQueue,
                    reportContext.sharesToBurnFromWithdrawalQueue
                );
            }
        }

        // Step 4.
        // Pass the accounting values to sanity checker to smoothen positive token rebase

        uint256 withdrawals;
        uint256 elRewards;
        (
            withdrawals, elRewards, reportContext.simulatedSharesToBurn, reportContext.sharesToBurn
        ) = IOracleReportSanityChecker(contracts.oracleReportSanityChecker).smoothenTokenRebase(
            reportContext.preTotalPooledEther,
            reportContext.preTotalShares,
            reportContext.preCLBalance,
            _reportedData.postCLBalance,
            _reportedData.withdrawalVaultBalance,
            _reportedData.elRewardsVaultBalance,
            _reportedData.sharesRequestedToBurn,
            reportContext.etherToLockOnWithdrawalQueue,
            reportContext.sharesToBurnFromWithdrawalQueue
        );

        // Step 5.
        // Invoke finalization of the withdrawal requests (send ether to withdrawal queue, assign shares to be burnt)
        _collectRewardsAndProcessWithdrawals(
            contracts,
            withdrawals,
            elRewards,
            _reportedData.withdrawalFinalizationBatches,
            _reportedData.simulatedShareRate,
            reportContext.etherToLockOnWithdrawalQueue
        );

        emit ETHDistributed(
            _reportedData.reportTimestamp,
            reportContext.preCLBalance,
            _reportedData.postCLBalance,
            withdrawals,
            elRewards,
            _getBufferedEther()
        );

        // Step 6.
        // Burn the previously requested shares
        if (reportContext.sharesToBurn > 0) {
            IBurner(contracts.burner).commitSharesToBurn(reportContext.sharesToBurn);
            _burnShares(contracts.burner, reportContext.sharesToBurn);
        }

        // Step 7.
        // Distribute protocol fee (treasury & node operators)
        reportContext.sharesMintedAsFees = _processRewards(
            reportContext,
            _reportedData.postCLBalance,
            withdrawals,
            elRewards
        );

        // Step 8.
        // Complete token rebase by informing observers (emit an event and call the external receivers if any)
        (
            uint256 postTotalShares,
            uint256 postTotalPooledEther
        ) = _completeTokenRebase(
            _reportedData,
            reportContext,
            IPostTokenRebaseReceiver(contracts.postTokenRebaseReceiver)
        );

        // Step 9. Sanity check for the provided simulated share rate
        if (_reportedData.withdrawalFinalizationBatches.length != 0) {
            IOracleReportSanityChecker(contracts.oracleReportSanityChecker).checkSimulatedShareRate(
                postTotalPooledEther,
                postTotalShares,
                reportContext.etherToLockOnWithdrawalQueue,
                reportContext.sharesToBurn.sub(reportContext.simulatedSharesToBurn),
                _reportedData.simulatedShareRate
            );
        }

        return [postTotalPooledEther, postTotalShares, withdrawals, elRewards];
    }

    /**
     * @dev Pass the provided oracle data to the sanity checker contract
     * Works with structures to overcome `stack too deep`
     */
    function _checkAccountingOracleReport(
        OracleReportContracts memory _contracts,
        OracleReportedData memory _reportedData,
        OracleReportContext memory _reportContext
    ) internal view {
        IOracleReportSanityChecker(_contracts.oracleReportSanityChecker).checkAccountingOracleReport(
            _reportedData.timeElapsed,
            _reportContext.preCLBalance,
            _reportedData.postCLBalance,
            _reportedData.withdrawalVaultBalance,
            _reportedData.elRewardsVaultBalance,
            _reportedData.sharesRequestedToBurn,
            _reportContext.preCLValidators,
            _reportedData.clValidators
        );
    }

    /**
     * @dev Notify observers about the completed token rebase.
     * Emit events and call external receivers.
     */
    function _completeTokenRebase(
        OracleReportedData memory _reportedData,
        OracleReportContext memory _reportContext,
        IPostTokenRebaseReceiver _postTokenRebaseReceiver
    ) internal returns (uint256 postTotalShares, uint256 postTotalPooledEther) {
        postTotalShares = _getTotalShares();
        postTotalPooledEther = _getTotalPooledEther();

        if (address(_postTokenRebaseReceiver) != address(0)) {
            _postTokenRebaseReceiver.handlePostTokenRebase(
                _reportedData.reportTimestamp,
                _reportedData.timeElapsed,
                _reportContext.preTotalShares,
                _reportContext.preTotalPooledEther,
                postTotalShares,
                postTotalPooledEther,
                _reportContext.sharesMintedAsFees
            );
        }

        emit TokenRebased(
            _reportedData.reportTimestamp,
            _reportedData.timeElapsed,
            _reportContext.preTotalShares,
            _reportContext.preTotalPooledEther,
            postTotalShares,
            postTotalPooledEther,
            _reportContext.sharesMintedAsFees
        );
    }

    /**
     * @dev Load the contracts used for `handleOracleReport` internally.
     */
    function _loadOracleReportContracts() internal view returns (OracleReportContracts memory ret) {
        (
            ret.accountingOracle,
            ret.elRewardsVault,
            ret.oracleReportSanityChecker,
            ret.burner,
            ret.withdrawalQueue,
            ret.withdrawalVault,
            ret.postTokenRebaseReceiver
        ) = getLidoLocator().oracleReportComponentsForLido();
    }

    function _stakingRouter() internal view returns (IStakingRouter) {
        return IStakingRouter(getLidoLocator().stakingRouter());
    }

    function _withdrawalQueue() internal view returns (IWithdrawalQueue) {
        return IWithdrawalQueue(getLidoLocator().withdrawalQueue());
    }

    function _treasury() internal view returns (address) {
        return getLidoLocator().treasury();
    }

    /**
     * @notice Mints shares on behalf of 0xdead address,
     * the shares amount is equal to the contract's balance.     *
     *
     * Allows to get rid of zero checks for `totalShares` and `totalPooledEther`
     * and overcome corner cases.
     *
     * NB: reverts if the current contract's balance is zero.
     *
     * @dev must be invoked before using the token
     */
    function _bootstrapInitialHolder() internal {
        uint256 balance = address(this).balance;
        assert(balance != 0);

        if (_getTotalShares() == 0) {
            // if protocol is empty bootstrap it with the contract's balance
            // address(0xdead) is a holder for initial shares
            _setBufferedEther(balance);
            // emitting `Submitted` before Transfer events to preserver events order in tx
            emit Submitted(INITIAL_TOKEN_HOLDER, balance, address(0));
            _mintInitialShares(balance);
        }
    }
}
