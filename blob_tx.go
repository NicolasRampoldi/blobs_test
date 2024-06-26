package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/holiman/uint256"
)

// SendBlobTX sends a transaction with an EIP-4844 blob payload to the Ethereum network.

const maxRetries = 10

type BlobTxResult struct {
	BeaconRoot       *common.Hash
	TransactionIndex uint
}

func sendBlobTX(rpcURL, data, privKey string) (*BlobTxResult, error) {
	// Connect to the Ethereum client
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to dial RPC client: %s", err)
	}
	defer client.Close() // Ensure the connection is closed after completing the function

	// Retrieve the current chain ID
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %s", err)
	}

	var Blob kzg4844.Blob // Define a blob array to hold the large data payload, blobs are 128kb in length

	// If necessary, convert the input data to a byte slice in hex format
	var bytesData []byte
	if data != "" {
		// Check if the data is in hex format, with or without the '0x' prefix
		if IsHexWithOrWithout0xPrefix(data) {
			// Ensure the data has the '0x' prefix
			if !strings.HasPrefix(data, "0x") {
				data = "0x" + data
			}
			// Decode the hex-encoded data
			bytesData, err = hexutil.Decode(data)
			if err != nil {
				return nil, fmt.Errorf("failed to decode data: %s", err)
			}
			// Copy the decoded data into the blob array
			copy(Blob[:], bytesData)
		} else {
			// If the data is not in hex format, copy it directly into the blob array
			copy(Blob[:], data)
		}
	}

	// Compute the commitment for the blob data using KZG4844 cryptographic algorithm
	BlobCommitment, err := kzg4844.BlobToCommitment(&Blob)
	if err != nil {
		return nil, fmt.Errorf("failed to compute blob commitment: %s", err)
	}

	// Compute the proof for the blob data, which will be used to verify the transaction
	BlobProof, err := kzg4844.ComputeBlobProof(&Blob, BlobCommitment)
	if err != nil {
		return nil, fmt.Errorf("failed to compute blob proof: %s", err)
	}

	// Prepare the sidecar data for the transaction, which includes the blob and its cryptographic proof
	sidecar := types.BlobTxSidecar{
		Blobs:       []kzg4844.Blob{Blob},
		Commitments: []kzg4844.Commitment{BlobCommitment},
		Proofs:      []kzg4844.Proof{BlobProof},
	}

	// Decode the sender's private key
	pKeyBytes, err := hexutil.Decode("0x" + privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %s", err)
	}

	// Convert the private key into the ECDSA format
	ecdsaPrivateKey, err := crypto.ToECDSA(pKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to ECDSA: %s", err)
	}

	// Compute the sender's address from the public key
	fromAddress := crypto.PubkeyToAddress(ecdsaPrivateKey.PublicKey)

	// Retrieve the nonce for the transaction
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)

	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %s", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %s", err)
	}

	println("Gas price:", gasPrice.String())

	gasTipCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get gas tip cap: %s", err)
	}

	println("Gas tip cap:", gasTipCap.String())

	lastBlock, err := client.BlockByNumber(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get last block: %s", err)
	}

	excessBlobGas := *lastBlock.ExcessBlobGas()
	calcBlobFee := eip4844.CalcBlobFee(excessBlobGas)
	blobFeeCap := uint256.MustFromBig(calcBlobFee)

	log.Println("blobFeeCap is: ", blobFeeCap)
	blobFeeCap.Mul(blobFeeCap, uint256.NewInt(2))
	log.Println("blobFeeCap will be send is: ", blobFeeCap)

	tip := lastBlock.BaseFee().Mul(lastBlock.BaseFee(), big.NewInt(10))
	log.Println("lastBlock.BaseFee() is: ", lastBlock.BaseFee())
	log.Println("tip is:                 ", tip)

	maxFeePerGas := lastBlock.BaseFee().Add(lastBlock.BaseFee(), tip)
	log.Println("maxFeePerGas is:        ", maxFeePerGas)

	blobGasUsed := *lastBlock.BlobGasUsed()
	log.Println("blobGasUsed is:                 ", blobGasUsed)

	transactions := lastBlock.Transactions()
	count := 0

	// Calculate the total number of blob txs
	for _, tx := range transactions {
		if tx.BlobHashes() != nil {
			count++
		}
	}

	var gas uint64

	log.Println("count is:                 ", count)

	if count == 0 {
		gas = 100_000
	} else {
		gas = blobGasUsed / uint64(count)
	}

	log.Println("gas is:                 ", gas)

	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, err
	}

	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(chainId),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(tip),
		GasFeeCap:  uint256.MustFromBig(maxFeePerGas),
		Gas:        gas,
		Value:      uint256.NewInt(0),
		Data:       nil,
		BlobFeeCap: blobFeeCap,
		BlobHashes: sidecar.BlobHashes(),
		Sidecar:    &sidecar,
	})
	log.Printf("Raw Tx is: %+v\n", tx)

	// gasTipCapU, overflow := uint256.FromBig(gasTipCap)
	// if overflow {
	// 	return nil, fmt.Errorf("failed to convert gas tip cap to uint256: %s", err)
	// }

	// Create the transaction with the blob data and cryptographic proofs
	// tx := types.NewTx(&types.BlobTx{
	// 	ChainID:   uint256.MustFromBig(chainID),
	// 	Nonce:     nonce,
	// 	GasTipCap: gasTipCapU, // max priority fee per gas
	// 	// GasFeeCap:  uint256.NewInt(50e10),      // max fee per gas
	// 	Gas: gas, // gas limit for the transaction
	// 	// To:  common.HexToAddress("0x0"), // recipient's address
	// 	// Value:      uint256.NewInt(0),          // value transferred in the transaction
	// 	// Data: nil, // No additional data is sent in this transaction
	// 	// BlobFeeCap: uint256.NewInt(3e10),       // fee cap for the blob data
	// 	BlobHashes: sidecar.BlobHashes(), // blob hashes in the transaction
	// 	Sidecar:    &sidecar,             // sidecar data in the transaction
	// })

	// Sign the transaction with the sender's private key
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), ecdsaPrivateKey)

	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %s", err)
	}

	// Send the signed transaction to the Ethereum network
	if err = client.SendTransaction(context.Background(), signedTx); err != nil {
		return nil, fmt.Errorf("failed to send transaction: %s", err)
	}

	txHash := signedTx.Hash()

	println("Transaction hash:", txHash.String())

	receipt, err := waitForTransactionReceipt(client, context.Background(), txHash)

	if err != nil {
		return nil, fmt.Errorf("failed to get transaction receipt: %s", err)
	}

	println("Transaction index:", receipt.TransactionIndex)

	blockNumber := receipt.BlockNumber

	// Add one because the beacon root of the current block is the parent beacon root of the next block.
	blockNumber.Add(blockNumber, big.NewInt(1))
	time.Sleep(12 * time.Second)
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %s", err)
	}

	println("Block number: ", block.NumberU64())
	// Parent beacon root and beacon root are the same
	println("Parent beacon root: ", block.Header().ParentBeaconRoot.String())
	println("Beacon root", block.BeaconRoot().String())

	res := &BlobTxResult{
		BeaconRoot:       block.Header().ParentBeaconRoot,
		TransactionIndex: receipt.TransactionIndex,
	}

	return res, nil
}

// IsHexWithOrWithout0xPrefix checks if a string is hex with or without `0x` prefix using regular expression.
func IsHexWithOrWithout0xPrefix(data string) bool {
	pattern := `^(0x)?[0-9a-fA-F]+$`
	matched, _ := regexp.MatchString(pattern, data)
	return matched
}

func waitForTransactionReceipt(client *ethclient.Client, ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	for i := 0; i < maxRetries; i++ {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err != nil {
			time.Sleep(30 * time.Second)
		} else {
			return receipt, nil
		}
	}
	return nil, fmt.Errorf("transaction receipt not found for txHash: %s", txHash.String())
}
