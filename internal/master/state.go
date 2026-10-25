// state.go handles persistence of master state: saving and loading the instance
// registry to/from disk using GOB serialization for crash recovery.
package master

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
)

// SaveState saves the current master state to disk using GOB serialization.
//
// Delegates to SaveStateToPath using the master's configured state file path.
// This is a convenience wrapper that centralizes state file management.
func (m *Master) SaveState() error {
	return m.SaveStateToPath(m.StatePath)
}

// SaveStateToPath saves the master state to a specific file path with atomic write semantics.
// It uses a temporary file to ensure data integrity during the save operation.
//
// Extracts all instances from the sync.Map and encodes them using GOB format. If the
// instance map is empty, removes the state file (if it exists). Otherwise, creates the
// directory structure if needed, writes to a temporary file first, then atomically
// renames it to the target path. This prevents corruption if the process crashes during
// write. All errors (mkdir, temp creation, encoding, file operations) are wrapped with
// context. The StateMu mutex ensures exclusive access during the save operation.
//
// Parameters:
//   - filePath: Full path where the state file should be saved
//
// Returns an error if any step of the save process fails.
func (m *Master) SaveStateToPath(filePath string) error {
	m.StateMu.Lock()
	defer m.StateMu.Unlock()

	m.dataMu.RLock()
	persistentData := make(map[string]*Instance)

	m.Instances.Range(func(key, value any) bool {
		instance := value.(*Instance)
		persistentData[key.(string)] = cloneInstance(instance)
		return true
	})

	m.dataMu.RUnlock()
	if len(persistentData) == 0 {
		if _, err := os.Stat(filePath); err == nil {
			return os.Remove(filePath)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("SaveStateToPath: mkdirAll failed: %w", err)
	}

	tempFile, err := os.CreateTemp(filepath.Dir(filePath), "np-*.tmp")
	if err != nil {
		return fmt.Errorf("SaveStateToPath: createTemp failed: %w", err)
	}
	tempPath := tempFile.Name()

	removeTemp := func() {
		if _, err := os.Stat(tempPath); err == nil {
			os.Remove(tempPath)
		}
	}

	encoder := gob.NewEncoder(tempFile)
	if err := encoder.Encode(persistentData); err != nil {
		tempFile.Close()
		removeTemp()
		return fmt.Errorf("SaveStateToPath: encode failed: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		removeTemp()
		return fmt.Errorf("SaveStateToPath: close temp file failed: %w", err)
	}

	if err := os.Rename(tempPath, filePath); err != nil {
		removeTemp()
		return fmt.Errorf("SaveStateToPath: rename temp file failed: %w", err)
	}

	return nil
}

// LoadState loads the master state from disk, initializes instances, and optionally auto-starts them.
// It cleans up any temporary files and handles state file deserialization.
//
// First cleans up any leftover temporary files (*.tmp) from previous failed saves. If the
// state file does not exist, returns silently (no instances to restore). Otherwise, opens
// the state file and decodes instances using GOB format. For each loaded instance, the
// "stopped" channel is re-initialized (since channels cannot be serialized). Non-API-key
// instances are set to "stopped" status. Missing configuration URLs are regenerated based
// on current master settings. If an instance has the Restart flag set, it is automatically
// started with a brief delay between starts. A summary log message reports how many
// instances were loaded.
func (m *Master) LoadState() error {
	file, err := os.Open(m.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var saved map[string]*Instance
	if err = gob.NewDecoder(file).Decode(&saved); err != nil {
		return fmt.Errorf("LoadState: decode failed: %w", err)
	}
	count := 0
	for id, i := range saved {
		if i == nil || id != i.ID {
			return fmt.Errorf("LoadState: invalid instance identity")
		}
		if id != APIKeyID {
			count++
			if err = validateInstance(i); err != nil {
				return fmt.Errorf("LoadState: %w", err)
			}
		}
	}
	if count > MaxManagedInstances {
		return fmt.Errorf("LoadState: managed instance limit reached")
	}
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	for id, i := range saved {
		i.stopped = make(chan struct{})
		if id != APIKeyID {
			i.Status = "stopped"
			if i.Config == "" {
				i.Config = m.GenerateConfigURL(i)
			}
		}
		if i.Meta.Tags == nil {
			i.Meta.Tags = map[string]string{}
		}
		m.Instances.Store(id, i)
	}
	for id, i := range saved {
		if id != APIKeyID && i.Restart {
			m.autostart = append(m.autostart, i)
		}
	}
	m.Logger.Info("Loaded %v instances from %v", len(saved), m.StatePath)
	return nil
}
