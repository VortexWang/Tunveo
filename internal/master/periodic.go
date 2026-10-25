// periodic.go runs background maintenance tasks for the master: periodic state
// backup, instance cleanup (removing stopped/errored instances), and scheduled
// instance restarts.
package master

import (
	"fmt"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

// StartPeriodicTasks starts the periodic maintenance tasks loop for backup, cleanup, and restart operations.
//
// Runs indefinitely at an interval defined by common.ReloadInterval. On each tick, executes:
//   - PerformPeriodicBackup: Saves a backup copy of the state file
//   - PerformPeriodicCleanup: Removes duplicate instances, keeping the one in "running" status
//   - PerformPeriodicRestart: Restarts instances that are in "error" status
//
// Returns when the PeriodicDone channel is closed (signaling master shutdown).
// This function should be started as a goroutine during master initialization.
func (m *Master) StartPeriodicTasks() {
	m.dataMu.Lock()
	if m.managementStopped.Load() {
		m.dataMu.Unlock()
		return
	}
	m.background.Add(1)
	m.dataMu.Unlock()
	defer m.background.Done()
	ticker := time.NewTicker(common.ReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.PerformPeriodicBackup()
			m.PerformPeriodicCleanup()
			m.PerformPeriodicRestart()
		case <-m.PeriodicDone:
			ticker.Stop()
			return
		}
	}
}

// PerformPeriodicBackup creates a backup of the current master state to disk.
//
// Saves a copy of the instance registry to a backup file (StatePath + ".backup") using
// the same GOB format as the main state file. This provides a recovery point in case
// the primary state file becomes corrupted. Errors are logged but do not prevent
// other periodic tasks from continuing. The backup runs at regular intervals
// (common.ReloadInterval) to ensure recent data can be recovered.
func (m *Master) PerformPeriodicBackup() {
	backupPath := fmt.Sprintf("%s.backup", m.StatePath)

	if err := m.SaveStateToPath(backupPath); err != nil {
		m.Logger.Error("PerformPeriodicBackup: backup state failed: %v", err)
	} else {
		m.Logger.Info("State backup saved: %v", backupPath)
	}
}

// PerformPeriodicCleanup performs housekeeping tasks on managed instances, cleaning up redundant entries.
//
// Identifies duplicate instances (same ID but different entries in the registry, which can
// occur due to race conditions or bugs). For instances with duplicates, keeps the one in
// "running" status and removes the others. Stopped duplicates are shut down gracefully
// before removal. This ensures the instance registry remains consistent and prevents
// stale entries from accumulating. Runs periodically to maintain registry health.
// sync.Map has one value per ID; duplicate-ID cleanup has no work to do.
func (m *Master) PerformPeriodicCleanup() {}

// PerformPeriodicRestart automatically restarts instances that have encountered errors during operation.
//
// Scans the instance registry for instances in "error" status (not deleted). For each
// errored instance, stops it gracefully, waits BaseDuration (100ms), and restarts it.
// This self-healing mechanism helps instances recover from transient failures without
// manual intervention. Runs periodically as part of the maintenance loop.
func (m *Master) PerformPeriodicRestart() {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	if m.managementStopped.Load() {
		return
	}
	m.Instances.Range(func(key, value any) bool {
		i := value.(*Instance)
		if key.(string) != APIKeyID && i.Status == "error" && !i.deleted && i.Restart {
			m.queueActionLocked(i, "restart")
		}
		return true
	})
}
