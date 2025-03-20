// SPDX-License-Identifier: LZBL-1.2
pragma solidity ^0.8.20;

import "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/interfaces/ILayerZeroDVN.sol";
import "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/interfaces/IDVNFeeLib.sol";
import "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/dvn/DVNFeeLib.sol";
import "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/dvn/adapters/DVNAdapterBase.sol";
import "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/dvn/adapters/libs/DVNAdapterMessageCodec.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {PacketV1Codec} from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import {ReceiveUlnBase} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/ReceiveUlnBase.sol";
import {IDVN} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/interfaces/IDVN.sol";
import {IReceiveUlnE2} from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/interfaces/IReceiveUlnE2.sol";
import {EndpointV2} from "../../dependencies/@layerzerolabs-lz-evm-protocol-v2-3.0.75/contracts/EndpointV2.sol";

/**
 * @title LayerZeroDVNInstance
 * @dev Basic DVN implementation that integrates with LayerZero ULN for verification
 */
contract LayerZeroDVNInstance is Worker, IDVN {
    EndpointV2 public immutable endpointV2;
    uint32 public immutable localEidV2; // endpoint-v2 only, for read call
    uint64 public immutable quorum;

    // Events
    event JobAssigned(uint32 dstEid, bytes32 payloadHash, uint64 confirmations, address sender);
    event FeeConfigSet(uint32 dstEid, uint256 baseFee);
    event MessageVerified(uint64 nonce, bytes32 payloadHash);
    event HashVerified(uint256 messageId, bytes32 hash);
    event VerifierFeePaid(uint256 fee);

    // State variables
    mapping(uint32 => uint256) public baseFees; // dstEid => base fee amount

    // Errors
    error MessageAlreadyVerified();
    error InvalidMessageHash();
    error VerificationFailed();
    error DstEidMismatch();
    error CustomVerificationFailed();

    mapping(uint32 => DstConfig) public dstConfig;

    /// @dev DVN doesn't have a roleAdmin (address(0x0))
    /// @dev Supports all of ULNv2, ULN301, ULN302 and more
    /// @param _endpoint endpoint address
    /// @param _messageLibs array of message lib addresses that are granted the MESSAGE_LIB_ROLE
    /// @param _priceFeed price feed address
    /// @param _signers array of signer addresses for multisig
    /// @param _quorum quorum for multisig
    /// @param _admins array of admin addresses that are granted the ADMIN_ROLE
    constructor(
        address _endpoint,
        address[] memory _messageLibs,
        address _priceFeed,
        address[] memory _signers,
        uint64 _quorum,
        address[] memory _admins
    ) Worker(_messageLibs, _priceFeed, 12000, address(0x0), _admins) {
        endpointV2 = EndpointV2(_endpoint);
        localEidV2 = endpointV2.eid();
        quorum = _quorum;
    }

    /**
     * @notice Called by LayerZero endpoint when a new verification job is assigned
     */
    function assignJob(
        AssignJobParam calldata _param,
        bytes calldata _options
    ) external payable onlyRole(MESSAGE_LIB_ROLE) onlyAcl(_param.sender) returns (uint256 totalFee) {
        // Calculate fee based on destination chain and confirmations
        totalFee = getFee(_param.dstEid, _param.confirmations, _param.sender, _options);
        require(msg.value >= totalFee, "LayerZeroDVNInstance: insufficient fee");

        // Emit event for off-chain DVN to pick up the job
        emit JobAssigned(_param.dstEid, _param.payloadHash, _param.confirmations, _param.sender);

        // Return excess fee
        if (msg.value > totalFee) {
            (bool success,) = msg.sender.call{value: msg.value - totalFee}("");
            require(success, "LayerZeroDVNInstance: failed to return excess fee");
        }

        emit VerifierFeePaid(totalFee);
        return totalFee;
    }

    /// @dev to support ReadLib
    // @param _packetHeader - version + nonce + path
    // @param _cmd - the command to be executed to obtain the payload
    // @param _options - options
    function assignJob(
        address _sender,
        bytes calldata /*_packetHeader*/,
        bytes calldata _cmd,
        bytes calldata _options
    ) external payable onlyRole(MESSAGE_LIB_ROLE) onlyAcl(_sender) returns (uint256 totalFee) {
        IDVNFeeLib.FeeParamsForRead memory feeParams = IDVNFeeLib.FeeParamsForRead(
            priceFeed,
            _sender,
            quorum,
            defaultMultiplierBps
        );
        totalFee = IDVNFeeLib(workerFeeLib).getFeeOnSend(feeParams, dstConfig[localEidV2], _cmd, _options);
        require(msg.value >= totalFee, "LayerZeroDVNInstance: insufficient fee");

        // Emit event for off-chain DVN to pick up the job
        emit JobAssigned(localEidV2, keccak256(_cmd), 0, _sender);

        // Return excess fee
        if (msg.value > totalFee) {
            (bool success,) = msg.sender.call{value: msg.value - totalFee}("");
            require(success, "LayerZeroDVNInstance: failed to return excess fee");
        }

        emit VerifierFeePaid(totalFee);
        return totalFee;
    }

    /**
     * @notice Verify a message from the off-chain DVN
     */
    function verifyMessageHash(bytes32 messageId, bytes memory packetHeader, bytes32 payloadHash)
    external
    onlyRole(ADMIN_ROLE)
    returns (bool)
    {
        // Decode packet header to get source and destination info
        (uint64 nonce, uint32 srcEid, uint32 dstEid, bytes32 receiver) = _decodePacketHeader(packetHeader);

        // TODO: Add custom verification logic here before allowing ULN verification
        // This is where we can add:
        // 1. Signature verification
        // 2. Zero-knowledge proof verification
        // 3. Custom security checks
        // 4. Multi-party computation results
        // 5. Oracle verification check
        // Example:
        // if (!verifyCustomSecurity(message, payloadHash)) {
        //     revert CustomVerificationFailed();
        // }

        // Verify the message using ULN contract
        (address receiveLibrary,) = endpointV2.getReceiveLibrary(address(uint160(uint256(receiver))), dstEid);
        IReceiveUlnE2(receiveLibrary).verify(
            packetHeader,
            payloadHash,
            type(uint64).max
        );

        emit MessageVerified(nonce, payloadHash);
        emit HashVerified(uint256(messageId), payloadHash);

        return true; // Success
    }

    /**
     * @notice Get the fee for verifying a packet
     */
    function getFee(uint32 _dstEid, uint64 _confirmations, address _sender, bytes calldata _options)
    public
    view
    override
    returns (uint256 fee)
    {
        uint256 baseFee = baseFees[_dstEid];

        IDVNFeeLib.FeeParams memory params = IDVNFeeLib.FeeParams(
            priceFeed,
            _dstEid,
            _confirmations,
            _sender,
            quorum,
            defaultMultiplierBps
        );
        uint256 dynamicFee = IDVNFeeLib(workerFeeLib).getFee(params, dstConfig[_dstEid], _options);
        return baseFee + dynamicFee;
    }

    /// @dev to support ReadLib
    // @param _packetHeader - version + nonce + path
    // @param _cmd - the command to be executed to obtain the payload
    // @param _options - options
    function getFee(
        address _sender,
        bytes calldata _packetHeader,
        bytes calldata _cmd,
        bytes calldata _options
    ) external view onlyAcl(_sender) returns (uint256 fee) {
        uint32 _dstEid = PacketV1Codec.dstEid(_packetHeader);

        uint256 baseFee = baseFees[_dstEid];

        IDVNFeeLib.FeeParamsForRead memory feeParams = IDVNFeeLib.FeeParamsForRead(
            priceFeed,
            _sender,
            quorum,
            defaultMultiplierBps
        );
        uint256 dynamicFee = IDVNFeeLib(workerFeeLib).getFee(feeParams, dstConfig[localEidV2], _cmd, _options);
        return baseFee + dynamicFee;
    }

    /**
     * @notice Decode packet header according to LayerZero format
     */
    function _decodePacketHeader(bytes memory packetHeader)
    internal
    pure
    returns (uint64 nonce, uint32 srcEid, uint32 dstEid, bytes32 receiver)
    {
        assembly {
        // Skip the first 32 bytes (the length)
            let data := add(packetHeader, 32)
            nonce := shr(192, mload(add(data, 1)))
            srcEid := shr(224, mload(add(data, 9)))
            dstEid := shr(224, mload(add(data, 45)))
            receiver := mload(add(data, 49))
        }
    }

    // Admin functions
    function setBaseFee(uint32 _dstEid, uint256 _baseFee) external onlyRole(ADMIN_ROLE) {
        baseFees[_dstEid] = _baseFee;
        emit FeeConfigSet(_dstEid, _baseFee);
    }

    /// @param _params array of DstConfigParam
    function setDstConfig(DstConfigParam[] calldata _params) external onlyRole(ADMIN_ROLE) {
        for (uint256 i = 0; i < _params.length; ++i) {
            DstConfigParam calldata param = _params[i];
            dstConfig[param.dstEid] = DstConfig(param.gas, param.multiplierBps, param.floorMarginUSD);
        }
        emit SetDstConfig(_params);
    }

    function withdraw(address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
        require(_to != address(0), "LayerZeroDVNInstance: invalid recipient");
        (bool success,) = _to.call{value: _amount}("");
        require(success, "LayerZeroDVNInstance: withdrawal failed");
    }
}
