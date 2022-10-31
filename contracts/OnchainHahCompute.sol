pragma solidity ^0.6.1;

// import '@openzeppelin/contracts/access/Ownable.sol';
import './lib/RollupHelpers.sol';

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