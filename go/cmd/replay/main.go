// Zantoras Evidence Replay Engine
// Auditor tool to import and verify evidence chain integrity
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Build info (set via ldflags)
var (
	Version   = "1.0.0"
	BuildTime = "unknown"
)

// NetFlowRecord matches the server's record format
type NetFlowRecord struct {
	Timestamp   int64  `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	BytesSent   int64  `json:"bytes_sent"`
	PacketCount int64  `json:"packet_count"`
	Payload     string `json:"payload,omitempty"`
}

// NetFlowBlob matches the server's blob format
type NetFlowBlob struct {
	BlobID         string        `json:"blob_id"`
	Timestamp      int64         `json:"timestamp"`
	Record         NetFlowRecord `json:"record"`
	PreviousHash   string        `json:"previous_hash"`
	Hash           string        `json:"hash"`
	DeviationScore float64       `json:"deviation_score"`
	IsAnomaly      bool          `json:"is_anomaly"`
}

// EvidenceExport matches the server's export format
type EvidenceExport struct {
	Version       string            `json:"version"`
	ExportedAt    string            `json:"exported_at"`
	ExportedBy    string            `json:"exported_by"`
	ChainHash     string            `json:"chain_hash"`
	BlobCount     int               `json:"blob_count"`
	FirstBlobHash string            `json:"first_blob_hash"`
	LastBlobHash  string            `json:"last_blob_hash"`
	TimeRange     map[string]string `json:"time_range"`
	Blobs         []NetFlowBlob     `json:"blobs"`
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "verify", "import":
		if len(os.Args) < 3 {
			fmt.Printf("%s%sError:%s Missing file path\n", colorBold, colorRed, colorReset)
			fmt.Println("Usage: zantoras-replay verify <evidence-export.json>")
			os.Exit(1)
		}
		verifyEvidence(os.Args[2])
	case "version", "--version", "-v":
		printVersion()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("%s%sError:%s Unknown command '%s'\n", colorBold, colorRed, colorReset, command)
		printUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("%s%sZantoras Evidence Replay Engine%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("Version: %s\n", Version)
	fmt.Printf("Build:   %s\n", BuildTime)
}

func printUsage() {
	fmt.Printf("\n%s%sZantoras Evidence Replay Engine%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("Auditor tool to verify evidence chain integrity\n\n")
	fmt.Printf("%sUsage:%s\n", colorBold, colorReset)
	fmt.Printf("  zantoras-replay verify <evidence-export.json>  Import and verify evidence chain\n")
	fmt.Printf("  zantoras-replay version                        Show version\n")
	fmt.Printf("  zantoras-replay help                           Show this help\n\n")
	fmt.Printf("%sExamples:%s\n", colorBold, colorReset)
	fmt.Printf("  zantoras-replay verify evidence-export-2026-02-03.json\n")
	fmt.Printf("  zantoras-replay verify ./exports/chain-backup.json\n\n")
}

func verifyEvidence(filePath string) {
	fmt.Printf("\n%s%s╔════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║       ZANTORAS EVIDENCE CHAIN VERIFICATION                 ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorCyan, colorReset)

	// Read the file
	fmt.Printf("%s[1/4]%s Loading evidence file...\n", colorYellow, colorReset)
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("  %s✗%s Failed to read file: %v\n\n", colorRed, colorReset, err)
		printVerificationFailed()
		os.Exit(1)
	}
	fmt.Printf("  %s✓%s File loaded: %s (%d bytes)\n\n", colorGreen, colorReset, filePath, len(data))

	// Parse JSON
	fmt.Printf("%s[2/4]%s Parsing evidence export...\n", colorYellow, colorReset)
	var export EvidenceExport
	if err := json.Unmarshal(data, &export); err != nil {
		fmt.Printf("  %s✗%s Failed to parse JSON: %v\n\n", colorRed, colorReset, err)
		printVerificationFailed()
		os.Exit(1)
	}
	fmt.Printf("  %s✓%s Export parsed successfully\n", colorGreen, colorReset)
	fmt.Printf("      Version:     %s\n", export.Version)
	fmt.Printf("      Exported At: %s\n", export.ExportedAt)
	fmt.Printf("      Exported By: %s\n", export.ExportedBy)
	fmt.Printf("      Blob Count:  %d\n", export.BlobCount)
	if export.TimeRange != nil {
		fmt.Printf("      Time Range:  %s to %s\n", export.TimeRange["start"], export.TimeRange["end"])
	}
	fmt.Println()

	// Verify individual blob hashes
	fmt.Printf("%s[3/4]%s Verifying blob hashes...\n", colorYellow, colorReset)
	blobHashErrors := 0
	chainErrors := 0

	for i, blob := range export.Blobs {
		// Recompute the hash
		hashInput := fmt.Sprintf("%s|%s|%d|%d|%s|%d|%d|%d|%s",
			blob.Record.SrcIP, blob.Record.DstIP, blob.Record.SrcPort, blob.Record.DstPort,
			blob.Record.Protocol, blob.Record.Timestamp, blob.Record.BytesSent, blob.Record.PacketCount,
			blob.PreviousHash)
		hashBytes := sha256.Sum256([]byte(hashInput))
		computedHash := fmt.Sprintf("%x", hashBytes)

		if computedHash != blob.Hash {
			blobHashErrors++
			if blobHashErrors <= 3 {
				fmt.Printf("  %s✗%s Blob %d hash mismatch:\n", colorRed, colorReset, i+1)
				fmt.Printf("      Expected: %s\n", blob.Hash[:32]+"...")
				fmt.Printf("      Computed: %s\n", computedHash[:32]+"...")
			}
		}

		// Verify chain linkage (skip first blob)
		if i > 0 {
			expectedPrevHash := export.Blobs[i-1].Hash
			if blob.PreviousHash != expectedPrevHash {
				chainErrors++
				if chainErrors <= 3 {
					fmt.Printf("  %s✗%s Blob %d chain break:\n", colorRed, colorReset, i+1)
					fmt.Printf("      Expected prev: %s\n", expectedPrevHash[:32]+"...")
					fmt.Printf("      Actual prev:   %s\n", blob.PreviousHash[:32]+"...")
				}
			}
		}
	}

	if blobHashErrors == 0 {
		fmt.Printf("  %s✓%s All %d blob hashes verified\n", colorGreen, colorReset, len(export.Blobs))
	} else {
		fmt.Printf("  %s✗%s %d/%d blobs have hash errors\n", colorRed, colorReset, blobHashErrors, len(export.Blobs))
	}

	if chainErrors == 0 {
		fmt.Printf("  %s✓%s Chain linkage intact\n\n", colorGreen, colorReset)
	} else {
		fmt.Printf("  %s✗%s %d chain breaks detected\n\n", colorRed, colorReset, chainErrors)
	}

	// Verify chain hash
	fmt.Printf("%s[4/4]%s Verifying chain hash...\n", colorYellow, colorReset)
	var chainHashInput strings.Builder
	for _, blob := range export.Blobs {
		chainHashInput.WriteString(blob.Hash)
	}
	chainHashBytes := sha256.Sum256([]byte(chainHashInput.String()))
	computedChainHash := fmt.Sprintf("%x", chainHashBytes)

	chainHashMatch := computedChainHash == export.ChainHash

	fmt.Printf("      Stored Chain Hash:   %s\n", export.ChainHash[:32]+"...")
	fmt.Printf("      Computed Chain Hash: %s\n", computedChainHash[:32]+"...")

	if chainHashMatch {
		fmt.Printf("  %s✓%s Chain hash verified\n\n", colorGreen, colorReset)
	} else {
		fmt.Printf("  %s✗%s Chain hash mismatch!\n\n", colorRed, colorReset)
	}

	// Final verdict
	printVerificationResult(blobHashErrors, chainErrors, chainHashMatch, export)
}

func printVerificationResult(blobErrors, chainErrors int, chainHashMatch bool, export EvidenceExport) {
	fmt.Printf("%s════════════════════════════════════════════════════════════════%s\n", colorCyan, colorReset)
	fmt.Printf("%s                    VERIFICATION RESULT%s\n", colorBold, colorReset)
	fmt.Printf("%s════════════════════════════════════════════════════════════════%s\n\n", colorCyan, colorReset)

	if blobErrors == 0 && chainErrors == 0 && chainHashMatch {
		// SUCCESS
		fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════╗%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("  %s%s║                                                          ║%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("  %s%s║   ✓ VERIFIED - EVIDENCE CHAIN INTEGRITY CONFIRMED       ║%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("  %s%s║                                                          ║%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorGreen, colorReset)

		fmt.Printf("  %sChain Hash:%s    %s\n", colorBold, colorReset, export.ChainHash)
		fmt.Printf("  %sBlobs Verified:%s %d\n", colorBold, colorReset, len(export.Blobs))
		fmt.Printf("  %sVerified At:%s   %s\n\n", colorBold, colorReset, time.Now().Format(time.RFC3339))

		fmt.Printf("  The evidence chain has not been tampered with.\n")
		fmt.Printf("  All cryptographic hashes match the expected values.\n\n")
	} else {
		// FAILURE
		fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════╗%s\n", colorBold, colorRed, colorReset)
		fmt.Printf("  %s%s║                                                          ║%s\n", colorBold, colorRed, colorReset)
		fmt.Printf("  %s%s║   ✗ FAILED - EVIDENCE TAMPERING DETECTED                 ║%s\n", colorBold, colorRed, colorReset)
		fmt.Printf("  %s%s║                                                          ║%s\n", colorBold, colorRed, colorReset)
		fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorRed, colorReset)

		fmt.Printf("  %sStored Chain Hash:%s   %s\n", colorBold, colorReset, export.ChainHash)
		fmt.Printf("  %sBlobs Checked:%s       %d\n", colorBold, colorReset, len(export.Blobs))
		fmt.Printf("  %sHash Errors:%s         %d\n", colorBold, colorReset, blobErrors)
		fmt.Printf("  %sChain Breaks:%s        %d\n", colorBold, colorReset, chainErrors)
		fmt.Printf("  %sChain Hash Match:%s    %v\n", colorBold, colorReset, chainHashMatch)
		fmt.Printf("  %sVerified At:%s         %s\n\n", colorBold, colorReset, time.Now().Format(time.RFC3339))

		fmt.Printf("  %s⚠ WARNING: This evidence chain has been modified!%s\n", colorRed, colorReset)
		fmt.Printf("  The cryptographic verification has failed, indicating\n")
		fmt.Printf("  potential tampering with the evidence data.\n\n")

		os.Exit(1)
	}
}

func printVerificationFailed() {
	fmt.Printf("%s════════════════════════════════════════════════════════════════%s\n", colorRed, colorReset)
	fmt.Printf("  %s%s✗ VERIFICATION FAILED - Unable to process evidence file%s\n", colorBold, colorRed, colorReset)
	fmt.Printf("%s════════════════════════════════════════════════════════════════%s\n\n", colorRed, colorReset)
}
