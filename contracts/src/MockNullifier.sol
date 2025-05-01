// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.6;

contract MockNullifierSystemContract {
    address public ward;

    constructor() {
        ward = msg.sender;
    }

    function nullify(bytes32 nullifier, bytes32 hash) public {
        require(msg.sender == ward);
        assembly {
            sstore(nullifier, hash)
        }
    }
}
