// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Local tests only. Simulates a changed asset implementation without any deployment script.
//
// Behaviors, set separately for `transfer` (configure) and `transferFrom`
// (configureTransferFrom):
//   0 standard ERC-20
//   1 returns true without moving any balance
//   2 delivers amount - 1 and burns 1 unit
//   3 calls `target` with `data` first (reentrancy), then behaves normally
//   4 returns false without moving any balance
//   5 delivers amount - 1 and sends 1 unit to FEE_COLLECTOR (fee on transfer)
contract AdversarialERC20 is ERC20 {
    address public constant FEE_COLLECTOR = address(0xFEE0);

    uint8 public behavior;
    address public callbackTarget;
    bytes public callbackData;
    bool public callbackSucceeded;

    uint8 public fromBehavior;
    address public fromCallbackTarget;
    bytes public fromCallbackData;
    bool public fromCallbackSucceeded;

    constructor() ERC20("Synthetic adversarial token", "TEST") {}

    function mint(address to, uint256 amount) external { _mint(to, amount); }

    function configure(uint8 mode, address target, bytes calldata data) external {
        behavior = mode; callbackTarget = target; callbackData = data;
    }

    function configureTransferFrom(uint8 mode, address target, bytes calldata data) external {
        fromBehavior = mode; fromCallbackTarget = target; fromCallbackData = data;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (behavior == 1) return true; // dishonest success with no movement
        if (behavior == 2) { _transfer(msg.sender, to, amount - 1); _burn(msg.sender, 1); return true; }
        if (behavior == 3) { (callbackSucceeded,) = callbackTarget.call(callbackData); }
        if (behavior == 4) return false;
        if (behavior == 5) { _transfer(msg.sender, to, amount - 1); _transfer(msg.sender, FEE_COLLECTOR, 1); return true; }
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (fromBehavior == 1) return true;
        if (fromBehavior == 2) {
            _spendAllowance(from, msg.sender, amount);
            _transfer(from, to, amount - 1);
            _burn(from, 1);
            return true;
        }
        if (fromBehavior == 3) { (fromCallbackSucceeded,) = fromCallbackTarget.call(fromCallbackData); }
        if (fromBehavior == 4) return false;
        if (fromBehavior == 5) {
            _spendAllowance(from, msg.sender, amount);
            _transfer(from, to, amount - 1);
            _transfer(from, FEE_COLLECTOR, 1);
            return true;
        }
        return super.transferFrom(from, to, amount);
    }
}
