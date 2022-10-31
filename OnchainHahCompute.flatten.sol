// Sources flattened with hardhat v2.12.1 https://hardhat.org

// File contracts/lib/Memory.sol

// solium-disable security/no-inline-assembly
pragma solidity ^0.6.1;

/**
* @title a library to sequentially read memory
* @dev inspired from Andreas Olofsson's RLP
*/
library Memory {
    struct Cursor {
       uint256 begin;
       uint256 end;
    }

    /**
    * @dev returns a new cursor from a memory
    * @return Cursor cursor to read from
    */
    function read(bytes memory self) internal pure returns (Cursor memory) {
       uint ptr;
       assembly {
         ptr := add(self, 0x20)
       }
       return Cursor(ptr,ptr+self.length);
    }

    /**
    * @dev reads 32 bytes from cursor, no eof checks
    * @return b the value
    */
    function readBytes32(Cursor memory c) internal pure returns (bytes32) {
        uint ptr = c.begin;
        bytes32 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 32;
        return b;
    }

    /**
    * @dev reads 30 bytes from cursor, no eof checks
    * @return b the value
    */
    function readBytes30(Cursor memory c) internal pure returns (bytes30) {
        uint ptr = c.begin;
        bytes32 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 30;
        return bytes30(b);
    }

    /**
    * @dev reads 28 bytes from cursor, no eof checks
    * @return b the value
    */
    function readBytes28(Cursor memory c) internal pure returns (bytes28) {
        uint ptr = c.begin;
        bytes32 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 28;
        return bytes28(b);
    }

    /**
    * @dev reads 10 bytes from cursor, no eof checks
    * @return b the value
    */
    function readBytes10(Cursor memory c) internal pure returns (bytes10) {
        uint ptr = c.begin;
        bytes32 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 10;
        return bytes10(b);
    }

    /**
    * @dev reads 3 bytes from cursor, no eof checks
    * @return b the value
    */
    function readBytes3(Cursor memory c) internal pure returns (bytes3) {
        uint ptr = c.begin;
        bytes32 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 3;
        return bytes3(b);
    }

    /**
    * @dev reads 2 bytes from cursor, no eof checks
    * @return b the value
    */
    function readBytes2(Cursor memory c) internal pure returns (bytes2) {
        uint ptr = c.begin;
        bytes32 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 2;
        return bytes2(b);
    }

    /**
    * @dev reads 1 bytes from cursor, no eof checks
    * @return b the value
    */
    function readBytes1(Cursor memory c) internal pure returns (bytes1) {
        uint ptr = c.begin;
        bytes32 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 1;
        return bytes1(b);
    }

    /**
    * @dev reads a bool from cursor (8 bits), no eof checks
    * @return b the value
    */
    function readBool(Cursor memory c) internal pure returns (bool) {
        uint ptr = c.begin;
        uint256 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 1;
        return (b >> (256-8)) != 0;
    }

    /**
    * @dev reads a uint8 from cursor, no eof checks
    * @return b the value
    */
    function readUint8(Cursor memory c) internal pure returns (uint8) {
        uint ptr = c.begin;
        uint256 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 1;
        return uint8(b >> (256-8));
    }

    /**
    * @dev reads a uint16 from cursor, no eof checks
    * @return b the value
    */
    function readUint16(Cursor memory c) internal pure returns (uint16) {
        uint ptr = c.begin;
        uint256 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 2;
        return uint16(b >> (256-16));
    }

    /**
    * @dev reads a uint32 from cursor, no eof checks
    * @return b the value
    */
    function readUint32(Cursor memory c) internal pure returns (uint32) {
        uint ptr = c.begin;
        uint256 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 4;
        return uint32(b >> (256-32));
    }

    /**
    * @dev reads a uint64 from cursor, no eof checks
    * @return b the value
    */
    function readUint64(Cursor memory c) internal pure returns (uint64) {
        uint ptr = c.begin;
        uint256 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 8;
        return uint64(b>>(256-64));
    }

    /**
    * @dev reads a uint240 from cursor, no eof checks
    * @return b the value
    */
    function readUint240(Cursor memory c) internal pure returns (uint240) {
        uint ptr = c.begin;
        uint256 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 30;
        return uint240(b>>(256-240));
    }

    /**
    * @dev reads an address from cursor, no eof checks
    * @return b the value
    */
    function readAddress(Cursor memory c) internal pure returns (address) {
        uint ptr = c.begin;
        uint256 b;
        assembly {
          b := mload(ptr)
        }
        c.begin += 20;
        return address(b >> (256-160));
    }

    /**
    * @dev reads a variable sized bytes, max 2^16 len, no eof check
    * @return bts the value
    */
    function readBytes(Cursor memory c) internal pure returns (bytes memory bts) {
        uint16 len = readUint16(c);
        bts = new bytes(len);
        uint256 btsmem;
        assembly {
            btsmem := add(bts,0x20)
        }
        memcpy(btsmem,c.begin,len);
        c.begin += len;
    }

    /**
    * @dev checks if the cursor is *exactly* at the end of the stream
    * @return c true if is *exactly* at the end
    */
    function eof(Cursor memory c) internal pure returns (bool) {
        return c.begin == c.end;
    }

    /**
    * @dev copies _len bytes from _src to _dest
    */
    // solium-disable security/no-assign-params
    function memcpy(uint _dest, uint _src, uint _len) internal pure {
        // Copy word-length chunks while possible
        for ( ;_len >= 32; _len -= 32) {
            assembly {
                mstore(_dest, mload(_src))
            }
            _dest += 32;
            _src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - _len) - 1;
        assembly {
            let srcpart := and(mload(_src), not(mask))
            let destpart := and(mload(_dest), mask)
            mstore(_dest, or(destpart, srcpart))
        }
    }

}


// File contracts/lib/RollupHelpers.sol

pragma solidity ^0.6.1;

/**
 * @dev Interface poseidon hash function
 */
contract PoseidonUnit {
  function poseidon(uint256[] memory) public pure returns(uint256) {}
}

/**
 * @dev Rollup helper functions
 */
contract RollupHelpers {

  using Memory for *;

  PoseidonUnit insPoseidonUnit;

  struct Entry {
    bytes32 e1;
    bytes32 e2;
    bytes32 e3;
    bytes32 e4;
    bytes32 e5;
    bytes32 e6;
  }

  uint constant bytesOffChainTx = 3*2 + 2;
  uint constant rField = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint64 constant IDEN3_ROLLUP_TX = 4839017969649077913;

  /**
   * @dev Load poseidon smart contract
   * @param _poseidonContractAddr poseidon contract address
   */
  constructor (address _poseidonContractAddr) public {
    insPoseidonUnit = PoseidonUnit(_poseidonContractAddr);
  }

  /**
   * @dev hash poseidon multi-input elements
   * @param inputs input element array
   * @return poseidon hash
   */
  function hashGeneric(uint256[] memory inputs) internal view returns (uint256){
    return insPoseidonUnit.poseidon(inputs);
  }

  /**
   * @dev hash poseidon for sparse merkle tree nodes
   * @param left input element array
   * @param right input element array
   * @return poseidon hash
   */
  function hashNode(uint256 left, uint256 right) internal view returns (uint256){
    uint256[] memory inputs = new uint256[](2);
    inputs[0] = left;
    inputs[1] = right;
    return hashGeneric(inputs);
  }

  /**
   * @dev hash poseidon for sparse merkle tree final nodes
   * @param key input element array
   * @param value input element array
   * @return poseidon hash1
   */
  function hashFinalNode(uint256 key, uint256 value) internal view returns (uint256){
    uint256[] memory inputs = new uint256[](3);
    inputs[0] = key;
    inputs[1] = value;
    inputs[2] = 1;
    return hashGeneric(inputs);
  }

  /**
   * @dev poseidon hash for entry generic structure
   * @param entry entry structure
   * @return poseidon hash
   */
  function hashEntry(Entry memory entry) internal view returns (uint256){
    uint256[] memory inputs = new uint256[](6);
    inputs[0] = uint256(entry.e1);
    inputs[1] = uint256(entry.e2);
    inputs[2] = uint256(entry.e3);
    inputs[3] = uint256(entry.e4);
    inputs[4] = uint256(entry.e5);
    inputs[5] = uint256(entry.e6);
    return hashGeneric(inputs);
  }

  /**
   * @dev Verify sparse merkle tree proof
   * @param root root to verify
   * @param siblings all siblings
   * @param key key to verify
   * @param value value to verify
   * @param isNonExistence existence or non-existence verification
   * @param isOld indicates non-existence non-empty verification
   * @param oldKey needed in case of non-existence proof with non-empty node
   * @param oldValue needed in case of non-existence proof with non-empty node
   * @return true if verification is correct, false otherwise
   */
  function smtVerifier(uint256 root, uint256[] memory siblings,
    uint256 key, uint256 value, uint256 oldKey, uint256 oldValue,
    bool isNonExistence, bool isOld, uint256 maxLevels) internal view returns (bool){

    // Step 1: check if proof is non-existence non-empty
    uint256 newHash;
    if (isNonExistence && isOld) {
      // Check old key is final node
      uint exist = 0;
      uint levCounter = 0;
      while ((exist == 0) && (levCounter < maxLevels)) {
        exist = (uint8(oldKey >> levCounter) & 0x01) ^ (uint8(key >> levCounter) & 0x01);
        levCounter += 1;
      }

      if (exist == 0) {
        return false;
      }
      newHash = hashFinalNode(oldKey, oldValue);
    }

    // Step 2: Calcuate root
    uint256 nextHash = isNonExistence ? newHash : hashFinalNode(key, value);
    uint256 siblingTmp;
    for (int256 i = int256(siblings.length) - 1; i >= 0; i--) {
     siblingTmp = siblings[uint256(i)];
      bool leftRight = (uint8(key >> i) & 0x01) == 1;
      nextHash = leftRight ? hashNode(siblingTmp, nextHash)
                           : hashNode(nextHash, siblingTmp);
    }

    // Step 3: Check root
    return root == nextHash;
  }

  /**
   * @dev build entry for fee plan
   * @param feePlan contains all fee plan data
   * @return entry structure
   */
  function buildEntryFeePlan(bytes32[2] memory feePlan)
    internal pure returns (Entry memory entry) {
    // build element 1
    entry.e1 = bytes32(feePlan[0] << 128) >> (256 - 128);
    // build element 2
    entry.e2 = bytes32(feePlan[0]) >> (256 - 128);
    // build element 3
    entry.e3 = bytes32(feePlan[1] << 128)>>(256 - 128);
    // build element 4
    entry.e4 = bytes32(feePlan[1]) >> (256 - 128);
  }

  /**
   * @dev Calculate total fee amount for the beneficiary
   * @param tokenIds contains all token id (feePlanCoinsInput)
   * @param totalFees contains total fee for every token Id (feeTotal)
   * @param nToken token position on fee plan
   * @return total fee amount
   */
  function calcTokenTotalFee(bytes32 tokenIds, bytes32 totalFees, uint nToken)
    internal pure returns (uint32, uint256) {
    uint256 ptr = 256 - ((nToken+1)*16);
    // get fee depending on token
    uint256 fee = float2Fix(uint16(bytes2(totalFees << ptr)));
    // get token id
    uint32 tokenId = uint16(bytes2(tokenIds << ptr));

    return (tokenId, fee);
  }

  /**
   * @dev build entry for the exit tree leaf
   * @param amount amount
   * @param token token type
   * @param Ax x coordinate public key babyJub
   * @param Ay y coordinate public key babyJub
   * @param ethAddress ethereum address
   * @param nonce nonce parameter
   * @return entry structure
   */
  function buildTreeState(uint256 amount, uint32 token, uint256 Ax, uint Ay,
    address ethAddress, uint48 nonce) internal pure returns (Entry memory entry) {
     // build element 1
    entry.e1 = bytes32(bytes4(token)) >> (256 - 32);
    entry.e1 |= bytes32(bytes6(nonce)) >> (256 - 48 - 32);
    // build element 2
    entry.e2 = bytes32(amount);
    // build element 3
    entry.e3 = bytes32(Ax);
    // build element 4
    entry.e4 = bytes32(Ay);
    // build element 5
    entry.e5 = bytes32(bytes20(ethAddress)) >> (256 - 160);
  }

  /**
   * @dev build transaction data
   * @param amountF amount to send encoded as half precision float
   * @param token token identifier
   * @param nonce nonce parameter
   * @param fee fee sent by the user, it represents some % of the amount
   * @param rqOffset atomic swap paramater
   * @param onChain flag to indicate that transaction is an onChain one
   * @param newAccount flag to indicate if transaction is of deposit type
   * @return element
   */
  function buildTxData(
    uint16 amountF,
    uint32 token,
    uint48 nonce,
    uint8 fee,
    uint8 rqOffset,
    bool onChain,
    bool newAccount
    ) internal pure returns (bytes32 element) {
    // build element
    element = bytes32(bytes8(IDEN3_ROLLUP_TX)) >> (256 - 64);
    element |= bytes32(bytes2(amountF)) >> (256 - 16 - 64);
    element |= bytes32(bytes4(token)) >> (256 - 32 - 16 - 64);
    element |= bytes32(bytes6(nonce)) >> (256 - 48 - 32 - 16 - 64);

    bytes1 nextByte = bytes1(fee) & 0x0f;
    nextByte = nextByte | (bytes1(rqOffset << 4) & 0x70);
    nextByte = onChain ? (nextByte | 0x80): nextByte;
    element |= bytes32(nextByte) >> (256 - 8 - 48 - 32 - 16 - 64);

    bytes1 last = newAccount ? bytes1(0x01) : bytes1(0x00);

    element |= bytes32(last) >> (256 - 8 - 8 - 48 - 32 - 16 - 64);
  }

  /**
   * @dev build on-chain Hash
   * @param oldOnChainHash previous on chain hash
   * @param txData transaction data coded into a bytes32
   * @param loadAmount input amount
   * @param dataOnChain poseidon hash of the onChain data
   * @param fromEthAddr ethereum addres sender
   * @return entry structure
   */
  function buildOnChainHash(
    uint256 oldOnChainHash,
    uint256 txData,
    uint128 loadAmount,
    uint256 dataOnChain,
    address fromEthAddr
    ) internal pure returns (Entry memory entry) {
    // build element 1
    entry.e1 = bytes32(oldOnChainHash);
    // build element 2
    entry.e2 = bytes32(txData);
    // build element 3
    entry.e3 = bytes32(bytes16(loadAmount)) >> (256 - 128);
    // build element 4
    entry.e4 = bytes32(dataOnChain);
    // build element 5
    entry.e5 = bytes32(bytes20(fromEthAddr)) >> (256 - 160);
  }

  /**
   * @dev build hash of the on-chain data
   * @param fromAx x coordinate public key BabyJubJub sender
   * @param fromAy y coordinate public key BabyJubJub sender
   * @param toEthAddr ethereum addres receiver
   * @param toAx x coordinate public key BabyJubJub receiver
   * @param toAy y coordinate public key BabyJubJub receiver
   * @return entry structure
   */
  function buildOnChainData(
    uint256 fromAx,
    uint256 fromAy,
    address toEthAddr,
    uint256 toAx,
    uint256 toAy
    ) internal pure returns (Entry memory entry) {
    // build element 1
    entry.e1 = bytes32(fromAx);
    // build element 2
    entry.e2 = bytes32(fromAy);
    // build element 3
    entry.e3 = bytes32(bytes20(toEthAddr)) >> (256 - 160);
    // build element 4
    entry.e4 = bytes32(toAx);
    // build element 5
    entry.e5 = bytes32(toAy);
  }

  /**
   * @dev Decode half floating precision
   * @param float Float half precision encode number
   * @return Decoded floating half precision
   */
  function float2Fix(uint16 float) public pure returns (uint256) {
    uint256 m = float & 0x3FF;
    uint256 e = float >> 11;
    uint256 e5 = (float >> 10) & 1;

    uint256 exp = 10 ** e;
    uint256 fix = m * exp;

    if ((e5 == 1) && (e != 0)){
      fix = fix + (exp / 2);
    }
    return fix;
  }

  /**
   * @dev Retrieve ethereum address from a msg plus signature
   * @param msgHash message hash
   * @param rsv signature
   * @return Ethereum address recovered from the signature
   */
  function checkSig(bytes32 msgHash, bytes memory rsv) public pure returns (address) {
    bytes32 r;
    bytes32 s;
    uint8   v;

    // solium-disable security/no-inline-assembly
    assembly {
        r := mload(add(rsv, 32))
        s := mload(add(rsv, 64))
        v := byte(0, mload(add(rsv, 96)))
    }
    return ecrecover(msgHash, v, r, s);
  }

  /**
   * @dev update on-chain fees
   * it updates every batch if it is full or build
   * @param onChainTxCount number of on-chain transactions in the same batch
   * @param currentFee current on-chain fee
   * @return newFee
   */
  function updateOnchainFee(uint256 onChainTxCount, uint256 currentFee) internal pure returns (uint256 newFee) {
      if (10 < onChainTxCount)
          newFee = (currentFee*100722)/100000;
      else if (10 > onChainTxCount)
          newFee = (currentFee*100000)/100722;
      else
          newFee = currentFee;
      if (newFee > 1 ether)
          newFee = 1 ether;
      else if (newFee < (1 szabo / 1000) ) // 1 Gwei
          newFee = 1 szabo / 1000;
  }

  /**
   * @dev update deposit fee
   * It updates every batch
   * @param depositCount number of deposits in the same batch
   * @param oldFee current deposit fee
   * @return newFee
   */
  function updateDepositFee(uint32 depositCount, uint256 oldFee) internal pure returns (uint256 newFee) {
      newFee = oldFee;
      for (uint32 i = 0; i < depositCount; i++) {
          newFee = newFee * 10000008235 / 10000000000;
      }
  }
}


// File contracts/OnchainHahCompute.sol

pragma solidity ^0.6.1;

// import '@openzeppelin/contracts/access/Ownable.sol';

contract Rollup is RollupHelpers {
    // Bytes of a encoded offchain deposit
    uint32 constant DEPOSIT_BYTES = 88;

    /**
     * @dev Rollup constructor
     * @param _poseidon poseidon hash function address
     */
    constructor(address _poseidon) RollupHelpers(_poseidon) public {
    }

    function getOnchainHash(bytes calldata compressedOnChainTx, uint256 initialHash) external view returns(uint256 finalOnchainHash_) {
        // Deposits that will be added in this batch
        uint64 depositOffChainLength = uint64(compressedOnChainTx.length/DEPOSIT_BYTES);

        finalOnchainHash_ = initialHash;
        // Add deposits off-chain
        for (uint32 i = 0; i < depositOffChainLength; i++) {  
            uint32 initialByte = DEPOSIT_BYTES*i;
            uint256 Ax = abi.decode(compressedOnChainTx[initialByte:initialByte+32], (uint256));
            uint256 Ay = abi.decode(compressedOnChainTx[initialByte+32:initialByte+64], (uint256));
            address ethAddress = address(abi.decode(compressedOnChainTx[initialByte+52:initialByte+84], (uint256)));
            uint32 token = uint32(abi.decode(compressedOnChainTx[initialByte+56:initialByte+88], (uint256)));
            
            finalOnchainHash_ = _addDepositOffChain(token, ethAddress, [Ax, Ay], finalOnchainHash_);
        }
    }

    function _addDepositOffChain(
        uint32 tokenId,
        address ethAddress,
        uint256[2] memory babyPubKey,
        uint256 initialHash
    ) internal view returns (uint256 onchainHash_) {
        // Build txData for deposit off-chain
        bytes32 txDataDeposit = buildTxData(0, tokenId, 0, 0, 0, true, true);

        // Calculate onChain Hash
        Entry memory onChainData = buildOnChainData(babyPubKey[0], babyPubKey[1],
        address(0), 0, 0);
        uint256 hashOnChainData = hashEntry(onChainData);
        Entry memory onChainHash = buildOnChainHash(initialHash, uint256(txDataDeposit), 0,
         hashOnChainData, ethAddress);
        onchainHash_ = hashEntry(onChainHash);
    }
}
