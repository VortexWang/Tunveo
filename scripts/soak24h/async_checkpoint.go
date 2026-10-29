package main

import (
    "encoding/json"
    "fmt"
    "os"
    "time"
)

// checkpointWriter serializes immutable snapshots in order. Its bounded queue
// fails closed rather than dropping an observation or hiding a slow writer.
type checkpointWriter struct {
    pending chan []byte
    done chan error
    terminal chan struct{}
}

func newCheckpointWriter(path string, capacity int, write func(string, []byte) error) *checkpointWriter {
    w := &checkpointWriter{pending: make(chan []byte, capacity), done: make(chan error, 1), terminal: make(chan struct{})}
    go func() {
        var failure error
        for data := range w.pending {
            if failure == nil { failure = write(path, data) }
        }
        w.done <- failure
        close(w.terminal)
    }()
    return w
}

func writeCheckpointBytes(path string, data []byte) error {
    if err := os.WriteFile(path+".tmp", data, 0600); err != nil { return err }
    return os.Rename(path+".tmp", path)
}

func (w *checkpointWriter) submit(r *result) error {
    data, err := json.MarshalIndent(r, "", "  ")
    if err != nil { return err }
    data = append(data, '\n')
    select {
    case <-w.terminal:
        return fmt.Errorf("checkpoint writer stopped unexpectedly")
    default:
    }
    select {
    case w.pending <- data: return nil
    default: return fmt.Errorf("checkpoint queue full; evidence incomplete")
    }
}

func (w *checkpointWriter) finish() error {
    close(w.pending)
    return <-w.done
}

// Timed external post-stop observers and multi-cycle mapping capture retain
// the synchronous publication contract until their handshake is qualified.
func asyncCheckpointEligible(cycles int, postStop time.Duration, diagnostics bool) bool {
    return cycles == 1 && postStop == 0 && !diagnostics
}
