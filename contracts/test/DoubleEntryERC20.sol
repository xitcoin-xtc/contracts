// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Local tests only. A token reachable through two addresses that share one
// balance ledger (the "double entry point" pattern). Used to check that a
// rescue of an apparently unrelated token address cannot move the canonical
// asset. XTC itself is a single ERC-1967 proxy and has no second entry point.
contract DoubleEntryERC20 is ERC20 {
    address public immutable secondaryEntry;

    constructor() ERC20("Synthetic double entry token", "TEST") {
        secondaryEntry = address(new SecondaryEntry(this));
    }

    function mint(address to, uint256 amount) external { _mint(to, amount); }

    function entryTransfer(address from, address to, uint256 amount) external returns (bool) {
        require(msg.sender == secondaryEntry, "only secondary entry");
        _transfer(from, to, amount);
        return true;
    }
}

contract SecondaryEntry {
    DoubleEntryERC20 public immutable primary;

    constructor(DoubleEntryERC20 primaryToken) { primary = primaryToken; }

    function balanceOf(address account) external view returns (uint256) {
        return primary.balanceOf(account);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return primary.entryTransfer(msg.sender, to, amount);
    }
}
