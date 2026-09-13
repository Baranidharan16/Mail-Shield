/*
 * MailShield - Hyperledger Fabric Evidence Chaincode (Go)
 * Smart contract for immutable evidence registration and tamper-evident verification.
 */
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// EvidenceSmartContract provides functions for managing forensic evidence records
type EvidenceSmartContract struct {
	contractapi.Contract
}

// EvidenceRecord describes the cryptographic metadata of preserved email forensic evidence
type EvidenceRecord struct {
	EvidenceID       string `json:"evidence_id"`
	CaseID           string `json:"case_id"`
	EvidenceHash     string `json:"evidence_hash"`
	EvidenceType     string `json:"evidence_type"`
	CaptureTimestamp string `json:"capture_timestamp"`
	Source           string `json:"source"`
	MessageID        string `json:"message_id"`
	AnalystID        string `json:"analyst_id"`
	PreviousHash     string `json:"previous_hash"`
	IntegrityStatus  string `json:"integrity_status"`
	TxTimestamp      string `json:"tx_timestamp"`
}

// RegisterEvidence registers a new cryptographic proof onto the Fabric state
func (s *EvidenceSmartContract) RegisterEvidence(
	ctx contractapi.TransactionContextInterface,
	evidenceID string,
	caseID string,
	evidenceHash string,
	evidenceType string,
	source string,
	messageID string,
	analystID string,
	previousHash string,
) error {
	exists, err := ctx.GetStub().GetState(evidenceID)
	if err != nil {
		return fmt.Errorf("failed to read world state: %v", err)
	}
	if exists != nil {
		return fmt.Errorf("evidence %s already registered and cannot be overwritten", evidenceID)
	}

	txTime, err := ctx.GetStub().GetTxTimestamp()
	timestampStr := time.Now().UTC().Format(time.RFC3339)
	if err == nil && txTime != nil {
		timestampStr = time.Unix(txTime.Seconds, int64(txTime.Nanos)).UTC().Format(time.RFC3339)
	}

	record := EvidenceRecord{
		EvidenceID:       evidenceID,
		CaseID:           caseID,
		EvidenceHash:     evidenceHash,
		EvidenceType:     evidenceType,
		CaptureTimestamp: timestampStr,
		Source:           source,
		MessageID:        messageID,
		AnalystID:        analystID,
		PreviousHash:     previousHash,
		IntegrityStatus:  "VERIFIED",
		TxTimestamp:      timestampStr,
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(evidenceID, recordBytes)
}

// GetEvidence retrieves an evidence proof record by evidenceID
func (s *EvidenceSmartContract) GetEvidence(
	ctx contractapi.TransactionContextInterface,
	evidenceID string,
) (*EvidenceRecord, error) {
	recordBytes, err := ctx.GetStub().GetState(evidenceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if recordBytes == nil {
		return nil, fmt.Errorf("evidence %s does not exist", evidenceID)
	}

	var record EvidenceRecord
	err = json.Unmarshal(recordBytes, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// VerifyEvidence compares an active SHA-256 hash against the immutable on-chain record
func (s *EvidenceSmartContract) VerifyEvidence(
	ctx contractapi.TransactionContextInterface,
	evidenceID string,
	currentHash string,
) (bool, error) {
	record, err := s.GetEvidence(ctx, evidenceID)
	if err != nil {
		return false, err
	}
	return (record.EvidenceHash == currentHash), nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(EvidenceSmartContract))
	if err != nil {
		fmt.Printf("Error create MailShield evidence chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting MailShield evidence chaincode: %s", err.Error())
	}
}
