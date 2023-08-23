// SPDX-License-Identifier: MIT
pragma solidity ^0.4.0;

contract AuditHashContract {
    mapping(uint64 => mapping(uint64 => string)) private AuditHash;

    function saveAuditHash(string memory hash, uint64 ctID, uint64 flowStartSec) public {
        AuditHash[ctID][flowStartSec] = hash;
    }

    function getAuditHash(uint64 ctID, uint64 flowStartSec) view public returns (string memory){
        return AuditHash[ctID][flowStartSec];
    }

    function verifyAuditHash(string memory hash, uint64 ctID, uint64 flowStartSec) view public returns (bool) {
        return keccak256(abi.encodePacked(hash)) == keccak256(abi.encodePacked(AuditHash[ctID][flowStartSec]));
    }
}

