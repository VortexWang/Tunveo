package master

import (
	"encoding/gob"
	"fmt"
	"os"
)

// ReadAPIKey reads existing local state without starting the master or creating
// a key. Callers must invoke this explicitly; it must never be used in logging.
func ReadAPIKey(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open master state: %w", err)
	}
	defer f.Close()
	var instances map[string]*Instance
	if err := gob.NewDecoder(f).Decode(&instances); err != nil {
		return "", fmt.Errorf("decode master state: %w", err)
	}
	entry := instances[APIKeyID]
	if entry == nil || entry.URL == "" {
		return "", fmt.Errorf("no API key in master state")
	}
	return entry.URL, nil
}
