// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncidentLog {
    event ThreatLogged(uint256 indexed id, uint256 timestamp, string srcIp, string dstIp, string severity, string details);

    struct ThreatEvent { uint256 id; uint256 timestamp; string srcIp; string dstIp; string severity; string details; }
    ThreatEvent[] public events;

    function logThreat(string memory srcIp, string memory dstIp, string memory severity, string memory details) public {
        ThreatEvent memory e = ThreatEvent({
            id: events.length,
            timestamp: block.timestamp,
            srcIp: srcIp,
            dstIp: dstIp,
            severity: severity,
            details: details
        });
        events.push(e);
        emit ThreatLogged(e.id, e.timestamp, e.srcIp, e.dstIp, e.severity, e.details);
    }

    function getEvent(uint256 id) public view returns (ThreatEvent memory) { return events[id]; }
    function getEventCount() public view returns (uint256) { return events.length; }
}
