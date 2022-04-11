//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract NameReg is Ownable, ERC721 {
  using SafeERC20 for IERC20;
  using ECDSA for bytes32;

  // lets assume name registration demands USDT locking
  address public USDT;

  // USDT amount to be locked for name registration
  uint256 public fee;  

  // name registration duration
  uint256 public regDuration;

  // name registration structure
  struct RegInfo {
    bytes32 name;
    uint256 regTime;
  }

  // name registration array
  RegInfo[] public regInfos;

  // name hash => registary info id
  mapping(bytes32 => uint256) public nameToRegId;

  // account => unlocked USDT amount
  mapping(address => uint256) public unlocked;

  // account => nonce
  mapping(address => uint256) private nonce;

  event Register(address indexed account, string name);
  event Renew(address indexed account, string name);
  event Sync(uint256 regId);

  constructor(
    address _USDT,
    uint256 _fee,
    uint256 _regDuration
  ) ERC721("Name Registration", "NR") {
    require(_USDT != address(0), "zero address");
    USDT = _USDT;
    fee = _fee;
    regDuration = _regDuration;
    regInfos.push(RegInfo({
      name: 0,
      regTime: 0
    }));
  }

  /**
   * @dev name register
   * user's private nonce is included in signature, so malicious frontrunner's tx would fail
   */
  function register(
    string memory _name,
    bytes memory _sig
  ) external {
    bytes32 nameHash = keccak256(abi.encodePacked(_name, ++nonce[msg.sender]));
    require(msg.sender == nameHash.recover(_sig), "invalid signature");

    require(bytes(_name).length != 0, "empty string");
    bytes32 name = keccak256(abi.encodePacked(_name));
    uint256 id = nameToRegId[name];
    if (id != 0) _sync(id);
    require(id == 0 || regInfos[id].regTime == 0, "duplicate name");
    IERC20(USDT).safeTransferFrom(msg.sender, address(this), fee);
    uint256 newId = regInfos.length;
    regInfos.push(RegInfo({
      name: name,
      regTime: block.timestamp
    }));
    nameToRegId[name] = newId;
    super._mint(msg.sender, newId);

    emit Register(msg.sender, _name);
  }

  /**
   * @dev name renew
   * user can renew expired name registration
   * his USDT would be locked again
   */
  function renew(string memory _name) external {
    require(bytes(_name).length != 0, "empty string");
    bytes32 name = keccak256(abi.encodePacked(_name));
    uint256 id = nameToRegId[name];
    uint256 unlocked_ = unlocked[msg.sender];
    require(ownerOf(id) == msg.sender, "caller not name owner");
    _sync(id);
    if (regInfos[id].regTime == 0 && unlocked_ >= fee) {
      regInfos[id].regTime = block.timestamp;
      unlocked[msg.sender] = unlocked_ - fee;

      emit Renew(msg.sender, _name);
    }
  }

  /**
   * @dev update expired `_name` and claim unlocked USDT
   */
  function claim(string memory _name) external {
    bytes32 name = keccak256(abi.encodePacked(_name));
    uint256 id = nameToRegId[name];
    require(ownerOf(id) == msg.sender, "caller not name owner");
    _sync(id);
    IERC20(USDT).safeTransfer(msg.sender, unlocked[msg.sender]);
    unlocked[msg.sender] = 0;
  }

  /**
   * @dev return nonce
   * everybody get only his nonce
   */
  function getNonce() external view returns(uint256) {
    return nonce[msg.sender];
  }

  /**
   * @dev update expired name registration
   */
  function _sync(uint256 _regId) private {
    require(_regId > 0 && _regId < regInfos.length, "reg id out of bounds");
    RegInfo memory reg = regInfos[_regId];
    if(reg.regTime != 0 && reg.regTime + regDuration <= block.timestamp) {
      unlocked[ownerOf(_regId)] += fee;
      regInfos[_regId].regTime = 0;

      emit Sync(_regId);
    }
  }  
}