// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// Builds the three message bodies. Packed, big-endian, exactly the layout `BridgeMessageCodec` reads
/// and `test-fixtures/bridge/messages-v1.json` pins.
///
/// ⚠ DELIBERATELY NOT BUILT WITH THE CODEC. A fixture that encodes with the same library the test
/// decodes with agrees with itself whatever the layout is. These are written out by hand so the two
/// sides can disagree.
library Messages {
    function credentialStatus(
        uint64 domainSeq,
        uint64 solidusHeight,
        bytes32 exportId,
        bytes32 issuerDidHash,
        bytes32 credentialTypeHash,
        bytes32 holder,
        uint8 status,
        uint64 validUntil,
        bool issuerAccredited
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(1),
            uint8(1),
            domainSeq,
            solidusHeight,
            exportId,
            issuerDidHash,
            credentialTypeHash,
            holder,
            status,
            validUntil,
            issuerAccredited ? uint8(1) : uint8(0)
        );
    }

    function issuerStatus(uint64 domainSeq, uint64 solidusHeight, bytes32 issuerDidHash, bool accredited)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(1), uint8(2), domainSeq, solidusHeight, issuerDidHash, accredited ? uint8(1) : uint8(0)
        );
    }

    function heartbeat(uint64 domainSeq, uint64 solidusHeight, uint64 solidusTimestamp, bytes32 globalRoot)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint8(1), uint8(3), domainSeq, solidusHeight, solidusTimestamp, globalRoot);
    }
}
