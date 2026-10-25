// event.go implements Server-Sent Events (SSE) streaming for real-time instance
// log and status updates, and manages the event dispatcher goroutine.
package master

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

// NewInstanceLogWriter creates a new InstanceLogWriter that parses instance output logs
// and extracts metrics and status information for real-time monitoring.
//
// The log writer processes child process output, looking for CHECK_POINT events
// containing instance metrics (mode, ping, pool size, connection stats). These
// metrics are extracted via regex and updated in the instance state. All output
// is simultaneously written to the target (usually stdout for logging purposes).
// The instance status is automatically updated from error to running when a
// CHECK_POINT is received.
//
// Parameters:
//   - instanceID: Unique identifier for the instance (for logging)
//   - instance: Pointer to the Instance being monitored
//   - target: io.Writer to receive all output (stdout, file, etc.)
//   - master: Reference to the Master for sending SSE events and accessing the instance registry
//
// Returns a new InstanceLogWriter configured with the CHECK_POINT regex pattern.
func NewInstanceLogWriter(instanceID string, instance *Instance, target io.Writer, master *Master) *InstanceLogWriter {
	return &InstanceLogWriter{
		InstanceID: instanceID,
		Instance:   instance,
		Target:     target,
		Master:     master,
		CheckPoint: regexp.MustCompile(`CHECK_POINT\|MODE=(\d+)\|PING=(\d+)ms\|POOL=(\d+)\|TCPS=(\d+)\|UDPS=(\d+)\|TCPRX=(\d+)\|TCPTX=(\d+)\|UDPRX=(\d+)\|UDPTX=(\d+)`),
	}
}

// Write processes instance log output, extracting metrics from CHECK_POINT events
// and forwarding logs to the target writer.
//
// Scans incoming log lines for CHECK_POINT events containing metrics like mode,
// ping latency, connection pool size, and traffic statistics. When a CHECK_POINT
// is found, the instance fields are updated with parsed values. Traffic counters
// account for resets by subtracting base and reset values. The instance status
// is automatically updated to "running" if it was in "error" state. Lines
// containing "Server error:" or "Client error:" mark the instance as errored.
// Non-CHECK_POINT lines are logged with the instance ID appended. All events
// trigger SSE broadcasts to subscribers.
//
// Parameters:
//   - p: Byte slice containing the log data to process
//
// Returns the number of bytes processed (always len(p)) and any scanning errors.
func (w *InstanceLogWriter) Write(p []byte) (n int, err error) {
	var output bytes.Buffer
	func() {
		w.Master.dataMu.Lock()
		defer w.Master.dataMu.Unlock()
		if current, ok := w.Master.Instances.Load(w.InstanceID); ok {
			w.Instance = current.(*Instance)
		}
		if w.Instance.deleted || (w.run != nil && w.Instance.run != w.run) {
			return
		}
		s := string(p)
		scanner := bufio.NewScanner(strings.NewReader(s))

		for scanner.Scan() {
			line := common.RedactLog(scanner.Text())
			if matches := w.CheckPoint.FindStringSubmatch(line); len(matches) == 10 {
				if mode, err := strconv.ParseInt(matches[1], 10, 32); err == nil {
					w.Instance.Mode = int32(mode)
				}
				if ping, err := strconv.ParseInt(matches[2], 10, 32); err == nil {
					w.Instance.Ping = int32(ping)
				}
				if pool, err := strconv.ParseInt(matches[3], 10, 32); err == nil {
					w.Instance.Pool = int32(pool)
				}
				if tcps, err := strconv.ParseInt(matches[4], 10, 32); err == nil {
					w.Instance.TCPS = int32(tcps)
				}
				if udps, err := strconv.ParseInt(matches[5], 10, 32); err == nil {
					w.Instance.UDPS = int32(udps)
				}

				stats := []*uint64{&w.Instance.TCPRX, &w.Instance.TCPTX, &w.Instance.UDPRX, &w.Instance.UDPTX}
				bases := []uint64{w.Instance.tcpRXBase, w.Instance.tcpTXBase, w.Instance.udpRXBase, w.Instance.udpTXBase}
				resets := []*uint64{&w.Instance.tcpRXReset, &w.Instance.tcpTXReset, &w.Instance.udpRXReset, &w.Instance.udpTXReset}
				for i, stat := range stats {
					if v, err := strconv.ParseUint(matches[i+6], 10, 64); err == nil {
						if v >= *resets[i] {
							*stat = bases[i] + v - *resets[i]
						} else {
							*stat = bases[i] + v
							*resets[i] = 0
						}
					}
				}

				w.Instance.lastCheckPoint = time.Now()

				if w.Instance.Status == "error" {
					w.Instance.Status = "running"
				}

				if !w.Instance.deleted {
					w.Master.Instances.Store(w.InstanceID, w.Instance)
					w.Master.sendSSEEventLocked("update", w.Instance)
				}
				continue
			}

			if w.Instance.Status != "error" && !w.Instance.deleted &&
				(strings.Contains(line, "Server error:") || strings.Contains(line, "Client error:")) {
				w.Instance.Status = "error"
				w.Instance.Ping = 0
				w.Instance.Pool = 0
				w.Instance.TCPS = 0
				w.Instance.UDPS = 0
				w.Master.Instances.Store(w.InstanceID, w.Instance)
			}

			fmt.Fprintf(&output, "%s [%s]\n", line, w.InstanceID)

			if !w.Instance.deleted {
				w.Master.sendSSEEventLocked("log", w.Instance, line)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(&output, "%s [%s]", common.RedactLog(s), w.InstanceID)
		}
	}()
	if output.Len() > 0 {
		if _, err := w.Target.Write(output.Bytes()); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// Subscriber data queues are never closed. Cancellation has a separate channel,
// so concurrent publication and retirement cannot send on a closed channel.
type eventSubscriber struct {
	events chan *InstanceEvent
	done   chan struct{}
	once   sync.Once
}

func (s *eventSubscriber) stop() { s.once.Do(func() { close(s.done) }) }
func (m *Master) removeSubscriber(id string, s *eventSubscriber) {
	m.sseMu.Lock()
	if m.Subscribers.CompareAndDelete(id, s) {
		m.sseCount--
	}
	s.stop()
	m.sseMu.Unlock()
}
func (m *Master) HandleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		HTTPError(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	// Revalidate under the same lock used for rotation and disconnect. An old-key
	// request admitted just before rotation must not subscribe after it completes.
	m.keyMu.RLock()
	status := m.credentialStatus(r)
	m.sseMu.Lock()
	if status == 0 && m.managementStopped.Load() {
		status = http.StatusServiceUnavailable
	}
	if status == 0 && m.sseCount >= ManagementSSELimit {
		status = http.StatusTooManyRequests
	}
	if status != 0 {
		m.sseMu.Unlock()
		m.keyMu.RUnlock()
		HTTPError(w, "SSE authentication or capacity unavailable", status)
		return
	}
	id := GenerateID()
	for {
		if _, exists := m.Subscribers.Load(id); !exists {
			break
		}
		id = GenerateID()
	}
	sub := &eventSubscriber{events: make(chan *InstanceEvent, 10), done: make(chan struct{})}
	m.Subscribers.Store(id, sub)
	m.sseCount++
	m.sseMu.Unlock()
	m.keyMu.RUnlock()
	defer m.removeSubscriber(id, sub)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	controller := http.NewResponseController(w)
	write := func(data []byte) bool {
		controller.SetWriteDeadline(time.Now().Add(ManagementWriteTimeout))
		if _, err := w.Write(data); err != nil {
			return false
		}
		if err := controller.Flush(); err != nil {
			return false
		}
		// A write budget bounds this frame, not the idle time until heartbeat.
		controller.SetWriteDeadline(time.Time{})
		return true
	}
	if !write([]byte(fmt.Sprintf("retry: %d\n\n", SSERetryTime))) {
		return
	}
	send := func(event *InstanceEvent) bool {
		if event.Instance != nil && event.Instance.ID == APIKeyID {
			return true
		}
		data, err := json.Marshal(event)
		if err != nil {
			return true
		}
		return write([]byte(fmt.Sprintf("event: instance\ndata: %s\n\n", data)))
	}
	for _, id := range m.instanceIDs() {
		select {
		case <-r.Context().Done():
			return
		case <-sub.done:
			return
		default:
		}
		instance, exists := m.FindInstance(id)
		if !exists {
			continue
		}
		if instance.ID != APIKeyID && !send(&InstanceEvent{Type: "initial", Time: time.Now(), Instance: instance}) {
			return
		}
	}

	ticker := time.NewTicker(ManagementHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.done:
			return
		case <-ticker.C:
			if !write([]byte(": heartbeat\n\n")) {
				return
			}
		case event := <-sub.events:
			if !send(event) {
				return
			}
		}
	}
}
func (m *Master) SendSSEEvent(eventType string, instance *Instance, logs ...string) {
	m.dataMu.RLock()
	defer m.dataMu.RUnlock()
	m.sendSSEEventLocked(eventType, instance, logs...)
}
func (m *Master) sendSSEEventLocked(eventType string, instance *Instance, logs ...string) {
	if instance != nil && instance.ID == APIKeyID {
		return
	}
	m.eventMu.RLock()
	defer m.eventMu.RUnlock()
	if m.eventsClosed || len(m.NotifyChannel) >= cap(m.NotifyChannel) {
		return
	}
	event := &InstanceEvent{Type: eventType, Time: time.Now(), Instance: cloneInstance(instance)}
	if len(logs) > 0 {
		event.Logs = logs[0]
	}

	select {
	case m.NotifyChannel <- event:
	default:
	}
}

// Used both by rotation and shutdown. Do not close subscriber data queues.
func (m *Master) ShutdownSSEConnections() {
	m.sseMu.Lock()
	defer m.sseMu.Unlock()
	m.Subscribers.Range(func(id, value any) bool { m.Subscribers.Delete(id); value.(*eventSubscriber).stop(); return true })
	m.sseCount = 0
}
func (m *Master) StartEventDispatcher() {
	for event := range m.NotifyChannel {
		if event.Instance != nil && event.Instance.ID == APIKeyID {
			continue
		}
		m.Subscribers.Range(func(_, value any) bool {
			sub := value.(*eventSubscriber)
			select {
			case <-sub.done:
			case sub.events <- event:
			default:
			}
			return true
		})
	}
}
