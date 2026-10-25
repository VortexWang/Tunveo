package master

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const MaxStateFileBytes = 128 << 20

type StateInspection struct {
	Format         string `json:"format"`
	Bytes          int    `json:"bytes"`
	SHA256         string `json:"sha256"`
	Instances      int    `json:"instances"`
	RestartEnabled int    `json:"restart_enabled"`
	APIKeyPresent  bool   `json:"api_key_present"`
	MIDPresent     bool   `json:"mid_present"`
}
type StateTransfer struct {
	Operation string `json:"operation"`
	StateInspection
	BackupCreated bool `json:"backup_created"`
	TargetCreated bool `json:"target_created"`
}

// This decoder is for local operator-owned GOB files, not an untrusted upload
// format. The byte ceiling does not bound every internal decoder allocation.
func readStateBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > MaxStateFileBytes {
		return nil, fmt.Errorf("state must be a regular file of at most %d bytes", MaxStateFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open state: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("state changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxStateFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if len(data) > MaxStateFileBytes {
		return nil, fmt.Errorf("state too large")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, fmt.Errorf("state changed while reading")
	}
	return data, nil
}
func decodeState(data []byte, requireCredentials bool) (map[string]*Instance, StateInspection, error) {
	summary := StateInspection{Format: "gob-map-v1", Bytes: len(data)}
	digest := sha256.Sum256(data)
	summary.SHA256 = hex.EncodeToString(digest[:])
	var saved map[string]*Instance
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&saved); err != nil {
		return nil, summary, fmt.Errorf("invalid state encoding")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, summary, fmt.Errorf("state contains trailing or invalid data")
	}
	for id, i := range saved {
		if i == nil || id != i.ID {
			return nil, summary, fmt.Errorf("invalid instance identity")
		}
		if id == APIKeyID {
			summary.APIKeyPresent = i.URL != ""
			summary.MIDPresent = i.Config != ""
			continue
		}
		summary.Instances++
		if i.Restart {
			summary.RestartEnabled++
		}
		if err := validateInstance(i); err != nil {
			return nil, summary, err
		}
	}
	if summary.Instances > MaxManagedInstances {
		return nil, summary, fmt.Errorf("managed instance limit reached")
	}
	if requireCredentials && (!summary.APIKeyPresent || !summary.MIDPresent) {
		return nil, summary, fmt.Errorf("state requires an existing API key and MID for identity-preserving transfer")
	}
	return saved, summary, nil
}
func InspectState(path string) (StateInspection, error) {
	data, err := readStateBytes(path)
	if err != nil {
		return StateInspection{}, err
	}
	_, summary, err := decodeState(data, true)
	return summary, err
}
func unusedDestination(path string) error {
	if path == "" {
		return fmt.Errorf("destination required")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return fmt.Errorf("destination must not exist: %s", path)
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("destination parent must be an existing directory: %s", parent)
	}
	return nil
}

// Publish a synced complete temporary file without replacing an existing name.
// Hard-link support is required; there is deliberately no check/rename fallback.
func publishStateCopy(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "tunveo-state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Link(temp.Name(), path); err != nil {
		return fmt.Errorf("publish without overwrite: %w", err)
	}
	if err = syncStateDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("destination published but directory sync failed; inspect before retrying: %w", err)
	}
	return nil
}

// TransferState never starts a master/child or changes the source. A published
// backup is retained if target publication fails. Both destinations must be new.
func TransferState(operation, source, target, backup string) (StateTransfer, error) {
	return transferState(operation, source, target, backup, publishStateCopy)
}
func transferState(operation, source, target, backup string, publish func(string, []byte) error) (StateTransfer, error) {
	result := StateTransfer{Operation: operation}
	if operation != "migrate" && operation != "restore" {
		return result, fmt.Errorf("unsupported transfer operation")
	}
	paths := []string{source, target}
	if operation == "migrate" {
		paths = append(paths, backup)
	} else if backup != "" {
		return result, fmt.Errorf("restore does not accept --backup")
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if path == "" {
			return result, fmt.Errorf("source, target and migration backup paths are required")
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return result, err
		}
		if seen[abs] {
			return result, fmt.Errorf("state paths must be distinct")
		}
		seen[abs] = true
	}
	data, err := readStateBytes(source)
	if err != nil {
		return result, err
	}
	_, summary, err := decodeState(data, true)
	if err != nil {
		return result, err
	}
	result.StateInspection = summary
	if err = unusedDestination(target); err != nil {
		return result, err
	}
	if operation == "migrate" {
		if err = unusedDestination(backup); err != nil {
			return result, err
		}
		if err = publish(backup, data); err != nil {
			return result, err
		}
		result.BackupCreated = true
	}
	if err = publish(target, data); err != nil {
		if result.BackupCreated {
			return result, fmt.Errorf("target publication failed; backup retained: %w", err)
		}
		return result, err
	}
	result.TargetCreated = true
	return result, nil
}
