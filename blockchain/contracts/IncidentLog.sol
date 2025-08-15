// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract IncidentLog {
    struct Incident {
        address reporter;
        uint256 timestamp;
        string details;
        string severity;
        string ipfsHash; // optional
    }

    event IncidentLogged(uint256 indexed id, address indexed reporter, uint256 timestamp, string severity);

    Incident[] public incidents;

    function logIncident(string memory details, string memory severity, string memory ipfsHash) public returns (uint256) {
        incidents.push(Incident({
            reporter: msg.sender,
            timestamp: block.timestamp,
            details: details,
            severity: severity,
            ipfsHash: ipfsHash
        }));
        uint256 id = incidents.length - 1;
        emit IncidentLogged(id, msg.sender, block.timestamp, severity);
        return id;
    }

    function getIncident(uint256 id) public view returns (Incident memory) {
        require(id < incidents.length, "out of range");
        return incidents[id];
    }

    function count() public view returns (uint256) {
        return incidents.length;
    }
}
