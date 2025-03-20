// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;

import {IMessageLibManager, SetConfigParam} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import {OApp, MessagingFee, Origin} from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import {OAppOptionsType3} from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OAppOptionsType3.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {OptionsBuilder} from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";

/**
 * @title ABAMock contract for demonstrating LayerZero messaging between blockchains.
 * @notice THIS IS AN EXAMPLE CONTRACT. DO NOT USE THIS CODE IN PRODUCTION.
 * @dev This contract showcases a PingPong style call (A -> B -> A) using LayerZero's OApp Standard.
 */
contract ABAMock is OApp, OAppOptionsType3 {
    using OptionsBuilder for bytes;
    bytes _options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(50000, 0);

    /// @notice Last received message data.
    string public data = "Nothing received yet";

    /// @notice Message types that are used to identify the various OApp operations.
    /// @dev These values are used in things like combineOptions() in OAppOptionsType3.
    uint16 public constant SEND = 1;
    uint16 public constant SEND_ABA = 2;

    /// @notice Emitted when a return message is successfully sent (B -> A).
    event ReturnMessageSent(string message, uint32 dstEid);

    /// @notice Emitted when a message is received from another chain.
    event MessageReceived(string message, uint32 senderEid, bytes32 sender);

    /// @notice Emitted when a message is sent to another chain (A -> B).
    event MessageSent(string message, uint32 dstEid);

    /// @dev Revert with this error when an invalid message type is used.
    error InvalidMsgType();

    /**
     * @dev Constructs a new PingPong contract instance.
     * @param _endpoint The LayerZero endpoint for this contract to interact with.
     * @param _owner The owner address that will be set as the owner of the contract.
     */
    constructor(address _endpoint, address _owner) OApp(_endpoint, _owner) {
        transferOwnership(msg.sender);
    }

    function encodeMessage(string memory _message, uint16 _msgType, bytes memory _extraReturnOptions) public pure returns (bytes memory) {
        // Get the length of _extraReturnOptions
        uint256 extraOptionsLength = _extraReturnOptions.length;

        // Encode the entire message, prepend and append the length of extraReturnOptions
        return abi.encode(_message, _msgType, extraOptionsLength, _extraReturnOptions, extraOptionsLength);
    }

    /**
     * @notice Returns the estimated messaging fee for a given message.
     * @param _dstEid Destination endpoint ID where the message will be sent.
     * @param _msgType The type of message being sent.
     * @param _message The message content.
     * @param _extraSendOptions Gas options for receiving the send call (A -> B).
     * @param _extraReturnOptions Additional gas options for the return call (B -> A).
     * @param _payInLzToken Boolean flag indicating whether to pay in LZ token.
     * @return fee The estimated messaging fee.
     */
    function quote(
        uint32 _dstEid,
        uint16 _msgType,
        string memory _message,
        bytes calldata _extraSendOptions,
        bytes calldata _extraReturnOptions,
        bool _payInLzToken
    ) public view returns (MessagingFee memory fee) {
        bytes memory payload = encodeMessage(_message, _msgType, _extraReturnOptions);
        bytes memory options = combineOptions(_dstEid, _msgType, _extraSendOptions);
        fee = _quote(_dstEid, payload, options, _payInLzToken);
    }

    /**
     * @notice Sends a message to a specified destination chain.
     * @param _dstEid Destination endpoint ID for the message.
     * @param _message The message content.
     */
    function send(
        uint32 _dstEid,
        string memory _message
    ) external payable {
        bytes memory _payload = abi.encode(_message);
        address payable _refundAddress = payable(address(this));

        _lzSend(
            _dstEid,
            _payload,
            _options,
            MessagingFee(msg.value, 0),
            _refundAddress
        );

        emit MessageSent(_message, _dstEid);
    }

    function decodeMessage(bytes calldata encodedMessage) public pure returns (string memory message, uint16 msgType, uint256 extraOptionsStart, uint256 extraOptionsLength) {
        extraOptionsStart = 256;  // Starting offset after _message, _msgType, and extraOptionsLength
        string memory _message;
        uint16 _msgType;

        // Decode the first part of the message
        (_message, _msgType, extraOptionsLength) = abi.decode(encodedMessage, (string, uint16, uint256));

        return (_message, _msgType, extraOptionsStart, extraOptionsLength);
    }

    /**
     * @notice Internal function to handle receiving messages from another chain.
     * @dev Decodes and processes the received message based on its type.
     * @param _origin Data about the origin of the received message.
     * @param message The received message content.
     */
    function _lzReceive(
        Origin calldata _origin,
        bytes32 /*guid*/,
        bytes calldata message,
        address,  // Executor address as specified by the OApp.
        bytes calldata  // Any extra data or options to trigger on receipt.
    ) internal override {

        (string memory _data) = abi.decode(message, (string));
        data = _data;

        emit MessageReceived(data, _origin.srcEid, _origin.sender);
    }

    function setConfigs(address _lib, SetConfigParam[] calldata _params) external {

        endpoint.setConfig(address(this), _lib, _params);
    }

    receive() external payable {}

}