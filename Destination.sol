// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./BridgeToken.sol";

contract Destination is AccessControl {
    bytes32 public constant WARDEN_ROLE  = keccak256("BRIDGE_WARDEN_ROLE");
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");

    mapping(address => address) public wrapped_tokens;
    mapping(address => address) public underlying_tokens;
    address[] public tokens;

    event Creation(address indexed underlying_token, address wrapped_token);
    event Wrap(address indexed underlying_token, address indexed wrapped_token, address indexed to, uint256 amount);
    event Unwrap(address indexed underlying_token, address indexed wrapped_token, address frm, address indexed to, uint256 amount);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CREATOR_ROLE, admin);
        _grantRole(WARDEN_ROLE, admin);
    }

    function createToken(address _underlying_token, string memory name, string memory symbol)
        public
        onlyRole(CREATOR_ROLE)
        returns (address)
    {
        require(_underlying_token != address(0), "Underlying cannot be zero");
        require(wrapped_tokens[_underlying_token] == address(0), "Already registered");

        BridgeToken token = new BridgeToken(_underlying_token, name, symbol, address(this));
        wrapped_tokens[_underlying_token] = address(token);
        underlying_tokens[address(token)] = _underlying_token;
        tokens.push(_underlying_token);

        emit Creation(_underlying_token, address(token));
        return address(token);
    }

    function wrap(address _underlying_token, address _recipient, uint256 _amount)
        public
        onlyRole(WARDEN_ROLE)
    {
        address wrapped = wrapped_tokens[_underlying_token];
        require(wrapped != address(0), "Token not registered");
        require(_recipient != address(0), "Recipient cannot be zero");
        require(_amount > 0, "Amount must be > 0");

        BridgeToken(wrapped).mint(_recipient, _amount);
        emit Wrap(_underlying_token, wrapped, _recipient, _amount);
    }

    function unwrap(address _wrapped_token, address _recipient, uint256 _amount) public {
        address underlying = underlying_tokens[_wrapped_token];
        require(underlying != address(0), "Wrapped token not recognized");
        require(_recipient != address(0), "Recipient cannot be zero");
        require(_amount > 0, "Amount must be > 0");

        BridgeToken(_wrapped_token).burn(_amount);
        emit Unwrap(underlying, _wrapped_token, msg.sender, _recipient, _amount);
    }

    function tokensCount() external view returns (uint256) {
        return tokens.length;
    }
}
