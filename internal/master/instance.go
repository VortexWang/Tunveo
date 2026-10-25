// instance.go manages the lifecycle of tunveo child-process instances:
// starting, stopping, monitoring, URL generation, and configuration updates.
package master

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

// FindInstance requires dataMu for mutable fields; IDs/credential URLs are
// stable outside transactions. Registry membership remains a sync.Map.
func (m *Master) FindInstance(id string) (*Instance, bool) {
	m.dataMu.RLock()
	defer m.dataMu.RUnlock()
	i, ok := m.findInstanceLocked(id)
	return cloneInstance(i), ok
}
func (m *Master) findInstanceLocked(id string) (*Instance, bool) {
	value, exists := m.Instances.Load(id)
	if !exists {
		return nil, false
	}
	i := value.(*Instance)
	return i, !i.deleted
}

type childRun struct {
	cmd       *exec.Cmd
	done      chan struct{}
	finalized chan struct{}
	stopping  bool // dataMu
}

func (m *Master) StartInstance(i *Instance) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	m.startInstanceLocked(i)
}
func (m *Master) startInstanceLocked(i *Instance) {
	current, ok := m.findInstanceLocked(i.ID)
	if !ok || i.ID == APIKeyID || m.managementStopped.Load() {
		return
	}
	i = current
	if i.run != nil || i.Status != "stopped" {
		return
	}
	if m.children >= MaxManagedChildren {
		i.Status = "error"
		m.sendSSEEventLocked("update", i)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		i.Status = "error"
		return
	}
	cmd := exec.Command(exe, i.URL)
	cmd.WaitDelay = GracefulTimeout
	run := &childRun{cmd: cmd, done: make(chan struct{}), finalized: make(chan struct{})}
	i.run = run
	i.cmd = cmd
	i.tcpRXBase = i.TCPRX
	i.tcpTXBase = i.TCPTX
	i.udpRXBase = i.UDPRX
	i.udpTXBase = i.UDPTX
	writer := NewInstanceLogWriter(i.ID, i, os.Stdout, m)
	writer.run = run
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err = cmd.Start(); err != nil {
		i.run = nil
		i.cmd = nil
		i.Status = "error"
		m.sendSSEEventLocked("update", i)
		return
	}
	m.children++
	m.runs.Store(run, cmd.Process)
	i.Status = "running"
	i.lastCheckPoint = time.Time{}
	m.Logger.Info("Instance starting: %v [%v] pid=%v", i.URL, i.ID, cmd.Process.Pid)
	go m.MonitorInstance(i, cmd)
	m.sendSSEEventLocked("update", i)
}

// Exactly one cmd.Wait owns process and pipe reaping for this generation.
func (m *Master) MonitorInstance(i *Instance, cmd *exec.Cmd) {
	m.dataMu.RLock()
	run := i.run
	m.dataMu.RUnlock()
	if run == nil || run.cmd != cmd {
		return
	}
	go func() {
		err := cmd.Wait()
		m.Logger.Info("Instance reaped [%v] pid=%v success=%v", i.ID, cmd.Process.Pid, err == nil)
		close(run.done) // Stop must be able to wake before this goroutine takes dataMu.
		m.dataMu.Lock()
		defer m.dataMu.Unlock()
		defer m.runs.Delete(run)
		defer close(run.finalized)
		m.children--
		if i.run != run {
			return
		}
		i.run = nil
		i.cmd = nil
		if run.stopping || err == nil {
			i.Status = "stopped"
		} else {
			i.Status = "error"
		}
		i.Ping = 0
		i.Pool = 0
		i.TCPS = 0
		i.UDPS = 0
		if !i.deleted {
			m.sendSSEEventLocked("update", i)
		}
	}()
	ticker := time.NewTicker(common.ReportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-run.done:
			return
		case <-ticker.C:
			m.dataMu.Lock()
			if i.run == run && !i.deleted && !run.stopping && !i.lastCheckPoint.IsZero() && time.Since(i.lastCheckPoint) > 3*common.ReportInterval {
				i.Status = "error"
				m.sendSSEEventLocked("update", i)
			}
			m.dataMu.Unlock()
		}
	}
}
func (m *Master) StopInstance(i *Instance) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	if value, ok := m.Instances.Load(i.ID); ok {
		m.stopInstanceLocked(context.Background(), value.(*Instance))
	}
}
func (m *Master) stopInstanceLocked(ctx context.Context, i *Instance) {
	run := i.run
	if run == nil {
		i.Status = "stopped"
		return
	}
	first := !run.stopping
	run.stopping = true
	m.dataMu.Unlock()
	if first {
		if runtime.GOOS == "windows" {
			run.cmd.Process.Signal(os.Interrupt)
		} else {
			run.cmd.Process.Signal(syscall.SIGTERM)
		}
	}
	timer := time.NewTimer(GracefulTimeout)
	select {
	case <-run.done:
	case <-ctx.Done():
		run.cmd.Process.Kill()
	case <-timer.C:
		run.cmd.Process.Kill()
	}
	timer.Stop()
	// A killed process remains tracked and charged until the sole Wait completes.
	select {
	case <-run.done:
	case <-time.After(GracefulTimeout):
	}
	m.dataMu.Lock()
	if i.run == run {
		select {
		case <-run.done:
			i.run = nil
			i.cmd = nil
			i.Status = "stopped"
			i.Ping = 0
			i.Pool = 0
			i.TCPS = 0
			i.UDPS = 0
		default:
		}
	}
	if !i.deleted {
		m.sendSSEEventLocked("update", i)
	}
}
func (m *Master) ProcessInstanceAction(i *Instance, action string) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	m.queueActionLocked(i, action)
}

// At most one action worker and one pending (latest) action per instance.
func (m *Master) queueActionLocked(i *Instance, action string) {
	current, ok := m.findInstanceLocked(i.ID)
	if !ok || m.managementStopped.Load() {
		return
	}
	i = current
	i.pendingAction = action
	if i.actionWorker {
		return
	}
	i.actionWorker = true
	m.background.Add(1)
	go func() {
		defer m.background.Done()
		m.dataMu.Lock()
		defer m.dataMu.Unlock()
		for {
			action := i.pendingAction
			i.pendingAction = ""
			if action == "" || i.deleted || m.managementStopped.Load() {
				i.actionWorker = false
				return
			}
			switch action {
			case "start":
				m.startInstanceLocked(i)
			case "stop":
				m.stopInstanceLocked(context.Background(), i)
			case "restart":
				m.stopInstanceLocked(context.Background(), i)
				if !i.deleted && !m.managementStopped.Load() {
					m.startInstanceLocked(i)
				}
			}
		}
	}()
}

// ReGenerateAPIKey generates a new API key and notifies all SSE clients.
//
// Generates a new 32-character hexadecimal API key and updates the API key instance.
// Logs rotation without the key value; authenticated responses still return the key. Persists the new key to the state file
// and gracefully shuts down all SSE connections, forcing clients to reconnect with
// the new key. This effectively invalidates all existing API keys, requiring clients
// to restart and authenticate with the new key.
//
// Parameters:
//   - instance: The API key instance (usually the special APIKeyID entry)
func (m *Master) ReGenerateAPIKey(instance *Instance) *Instance {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	return cloneInstance(m.regenerateAPIKeyLocked(instance))
}
func (m *Master) regenerateAPIKeyLocked(instance *Instance) *Instance {
	m.keyMu.Lock()
	if current, ok := m.findInstanceLocked(APIKeyID); ok {
		instance = current
	}
	next := *instance
	next.URL = GenerateAPIKey()
	instance = &next
	m.Instances.Store(APIKeyID, instance)
	m.ShutdownSSEConnections()
	m.keyMu.Unlock()
	m.Logger.Info("API Key regenerated; use tunveo api-key --state <state-file> for local retrieval")
	m.requestSaveLocked()
	return instance
}

// EnhanceURL adds master configuration parameters to an instance URL.
// It parses the URL, updates query parameters based on master settings and instance type,
// and returns the enhanced URL string.
//
// If the master has LogLevel configured and the URL doesn't already specify "log",
// adds the master's log level to the query. For server instances with TLS enabled
// (tlsCode != "0"), adds the TLS mode. If TLS mode is "2" (custom certs), adds the
// certificate and key file paths if not already specified. This allows master-wide
// configuration to be injected into instance URLs while respecting explicit URL parameters.
// Server instances also receive the default pool backend if none is configured.
//
// Parameters:
//   - instanceURL: The instance URL to enhance (scheme://[user@]host:port/path?query)
//   - instanceType: The instance type ("server" or "client")
//
// Returns the enhanced URL string, or the original URL if parsing fails.
func (m *Master) EnhanceURL(instanceURL string, instanceType string) string {
	parsedURL, err := url.Parse(instanceURL)
	if err != nil {
		m.Logger.Error("EnhanceURL: invalid URL format")
		return instanceURL
	}

	query := parsedURL.Query()

	if m.LogLevel != "" && query.Get("log") == "" {
		query.Set("log", m.LogLevel)
	}

	if instanceType == "server" && m.TLSCode != "0" {
		if query.Get("tls") == "" {
			query.Set("tls", m.TLSCode)
		}

		if m.TLSCode == "2" {
			if m.CrtPath != "" && query.Get("crt") == "" {
				query.Set("crt", m.CrtPath)
			}
			if m.KeyPath != "" && query.Get("key") == "" {
				query.Set("key", m.KeyPath)
			}
		}
	}
	if instanceType == "server" && query.Get("type") == "" {
		query.Set("type", common.DefaultPoolType)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// GenerateConfigURL generates a full configuration URL for an instance.
// It parses the URL, updates query parameters based on master settings and instance type,
// and returns the enhanced URL string.
//
// Similar to EnhanceURL, but also adds sensible default parameters for clients and servers
// if not already specified. For clients, includes DNS TTL, SNI, load balancing strategy,
// pool size, mode, source IP, read timeout, rate limit, connection slots, PROXY protocol,
// blocked protocols, and TCP/UDP enable/disable flags. Servers get DNS TTL, load balancing,
// max pool size, mode, pool backend, source IP, timeouts, rate limits, and protocol settings. Master-level
// TLS and log settings are also applied. This ensures every instance has a complete,
// runnable configuration derived from master defaults and explicit instance parameters.
//
// Parameters:
//   - instance: The instance to generate config for
//
// Returns the full configuration URL string.
func (m *Master) GenerateConfigURL(instance *Instance) string {
	parsedURL, err := url.Parse(instance.URL)
	if err != nil {
		m.Logger.Error("GenerateConfigURL: invalid URL format")
		return instance.URL
	}

	query := parsedURL.Query()

	if m.LogLevel != "" && query.Get("log") == "" {
		query.Set("log", m.LogLevel)
	}

	if instance.Type == "server" && m.TLSCode != "0" {
		if query.Get("tls") == "" {
			query.Set("tls", m.TLSCode)
		}

		if m.TLSCode == "2" {
			if m.CrtPath != "" && query.Get("crt") == "" {
				query.Set("crt", m.CrtPath)
			}
			if m.KeyPath != "" && query.Get("key") == "" {
				query.Set("key", m.KeyPath)
			}
		}
	}

	switch instance.Type {
	case "client":
		if query.Get("dns") == "" {
			query.Set("dns", common.DefaultDNSTTL.String())
		}
		if query.Get("sni") == "" {
			query.Set("sni", common.DefaultServerName)
		}
		if query.Get("lbs") == "" {
			query.Set("lbs", common.DefaultLBStrategy)
		}
		if query.Get("min") == "" {
			query.Set("min", strconv.Itoa(common.DefaultMinPool))
		}
		if query.Get("mode") == "" {
			query.Set("mode", common.DefaultRunMode)
		}
		if query.Get("type") == "" {
			query.Set("type", common.DefaultPoolType)
		}
		if query.Get("dial") == "" {
			query.Set("dial", common.DefaultDialerIP)
		}
		if query.Get("read") == "" {
			query.Set("read", common.DefaultReadTimeout.String())
		}
		if query.Get("rate") == "" {
			query.Set("rate", strconv.Itoa(common.DefaultRateLimit))
		}
		if query.Get("slot") == "" {
			query.Set("slot", strconv.Itoa(common.DefaultSlotLimit))
		}
		if query.Get("proxy") == "" {
			query.Set("proxy", common.DefaultProxyProtocol)
		}
		if query.Get("block") == "" {
			query.Set("block", common.DefaultBlockProtocol)
		}
		if query.Get("notcp") == "" {
			query.Set("notcp", common.DefaultTCPStrategy)
		}
		if query.Get("noudp") == "" {
			query.Set("noudp", common.DefaultUDPStrategy)
		}
	case "server":
		if query.Get("dns") == "" {
			query.Set("dns", common.DefaultDNSTTL.String())
		}
		if query.Get("lbs") == "" {
			query.Set("lbs", common.DefaultLBStrategy)
		}
		if query.Get("max") == "" {
			query.Set("max", strconv.Itoa(common.DefaultMaxPool))
		}
		if query.Get("mode") == "" {
			query.Set("mode", common.DefaultRunMode)
		}
		if query.Get("dial") == "" {
			query.Set("dial", common.DefaultDialerIP)
		}
		if query.Get("read") == "" {
			query.Set("read", common.DefaultReadTimeout.String())
		}
		if query.Get("rate") == "" {
			query.Set("rate", strconv.Itoa(common.DefaultRateLimit))
		}
		if query.Get("slot") == "" {
			query.Set("slot", strconv.Itoa(common.DefaultSlotLimit))
		}
		if query.Get("proxy") == "" {
			query.Set("proxy", common.DefaultProxyProtocol)
		}
		if query.Get("block") == "" {
			query.Set("block", common.DefaultBlockProtocol)
		}
		if query.Get("notcp") == "" {
			query.Set("notcp", common.DefaultTCPStrategy)
		}
		if query.Get("noudp") == "" {
			query.Set("noudp", common.DefaultUDPStrategy)
		}
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// SetInstanceURL updates an instance's URL configuration with the provided parameters,
// stops the running instance if necessary, and restarts it with the new configuration.
//
// Parses the instance's current URL and applies updates to the URL components or query
// parameters. Supports updating "type" (scheme), "pool" (query type), "password" (auth), "tunnel_address",
// "tunnel_port", "target_address", "target_port", "targets" (path), and any query
// parameters. Query parameter values are replaced or deleted (if empty). Validates that
// the type is "client" or "server". Returns an error if no changes are detected.
// Stops the instance if running, replaces the URL, regenerates the config, and restarts.
// The new state is persisted asynchronously and an SSE update event is sent.
//
// Parameters:
//   - instance: The instance to update
//   - updates: Map of field names to new values
//
// Returns an error if the URL is invalid, type is invalid, or no changes detected.
func (m *Master) SetInstanceURL(instance *Instance, updates map[string]string) error {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	current, ok := m.findInstanceLocked(instance.ID)
	if !ok {
		return fmt.Errorf("instance not found")
	}
	return m.setInstanceURLLocked(current, updates)
}
func (m *Master) setInstanceURLLocked(instance *Instance, updates map[string]string) error {
	parsedURL, err := url.Parse(instance.URL)
	if err != nil {
		return fmt.Errorf("SetInstanceURL: invalid URL format: %w", err)
	}

	newType := instance.Type
	query := parsedURL.Query()

	for key, value := range updates {
		switch key {
		case "type":
			if value != "client" && value != "server" {
				return fmt.Errorf("SetInstanceURL: invalid type: must be 'client' or 'server'")
			}
			parsedURL.Scheme = value
			newType = value
		case "pool":
			if value == "" {
				query.Del("type")
			} else {
				query.Set("type", value)
			}
		case "password":
			if value == "" {
				parsedURL.User = nil
			} else {
				parsedURL.User = url.User(value)
			}
		case "tunnel_address":
			parsedURL.Host = value + ":" + parsedURL.Port()
		case "tunnel_port":
			parsedURL.Host = parsedURL.Hostname() + ":" + value
		case "target_address", "target_port":
			pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), ":")
			if key == "target_address" {
				pathParts[0] = value
			} else if len(pathParts) > 1 {
				pathParts[1] = value
			} else {
				pathParts = append(pathParts, value)
			}
			parsedURL.Path = "/" + strings.Join(pathParts, ":")
		case "targets":
			parsedURL.Path = "/" + value
		default:
			if value == "" {
				query.Del(key)
			} else {
				query.Set(key, value)
			}
		}
	}

	parsedURL.RawQuery = query.Encode()
	newURL := parsedURL.String()

	proposed := cloneInstance(instance)
	proposed.URL = newURL
	proposed.Type = newType
	if err := validateInstance(proposed); err != nil {
		return err
	}
	if newURL == instance.URL {
		return fmt.Errorf("SetInstanceURL: no changes detected")
	}

	if instance.Status != "stopped" {
		m.stopInstanceLocked(context.Background(), instance)
		time.Sleep(BaseDuration)
	}

	if instance.deleted || m.managementStopped.Load() {
		return fmt.Errorf("instance no longer mutable")
	}
	instance.Type = newType
	instance.URL = newURL
	instance.Config = m.GenerateConfigURL(instance)
	instance.Status = "stopped"
	m.Instances.Store(instance.ID, instance)

	m.queueActionLocked(instance, "start")
	m.requestSaveLocked()

	return nil
}
