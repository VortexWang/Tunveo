package http2

import (
	"io"
	"net"
	"sync"
	"time"
)

// deadlineIO gives each logical stream independent, resettable net.Conn deadlines.
// Two lazy pumps stage at most one 32 KiB chunk per direction. Bytes accepted by
// Write may still be in that staging buffer, as with a buffered network socket.
// An expired deadline does not cancel the HTTP/2 request or its sibling streams.
type deadlineIO struct {
	raw                      io.ReadWriteCloser
	read, readPump           net.Conn
	write, writePump         net.Conn
	writeMu                  sync.Mutex
	pendingAck               bool
	mu                       sync.Mutex
	closed, reading, writing bool
	readErr, writeErr        error
	wg                       sync.WaitGroup
	once                     sync.Once
	done                     chan struct{}
	err                      error
}

func newDeadlineIO(raw io.ReadWriteCloser) *deadlineIO {
	r, rp := net.Pipe()
	w, wp := net.Pipe()
	return &deadlineIO{raw: raw, read: r, readPump: rp, write: w, writePump: wp, done: make(chan struct{})}
}
func (s *deadlineIO) start(read bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	started := &s.writing
	if read {
		started = &s.reading
	}
	if *started {
		return true
	}
	*started = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var err error
		if read {
			_, err = io.CopyBuffer(s.readPump, s.raw, make([]byte, 32<<10))
		} else {
			// A successful public Write waits for this acknowledgement. In
			// particular, a TLS verification ACK must reach Flush before Close.
			buf := make([]byte, 32<<10)
			for {
				n, readErr := s.writePump.Read(buf)
				if n > 0 {
					written, writeErr := s.raw.Write(buf[:n])
					if writeErr == nil && written != n {
						writeErr = io.ErrShortWrite
					}
					if writeErr != nil {
						err = writeErr
						break
					}
					if _, err = s.writePump.Write([]byte{1}); err != nil {
						break
					}
				}
				if readErr != nil {
					err = readErr
					break
				}
			}
		}
		s.mu.Lock()
		if read {
			s.readErr = err
		} else {
			s.writeErr = err
		}
		s.mu.Unlock()
		if read {
			s.readPump.Close()
		} else {
			s.writePump.Close()
		}
	}()
	return true
}
func (s *deadlineIO) Read(p []byte) (int, error) {
	if !s.start(true) {
		return 0, net.ErrClosed
	}
	n, err := s.read.Read(p)
	if err == io.EOF {
		s.mu.Lock()
		upstream := s.readErr
		s.mu.Unlock()
		if upstream != nil {
			err = upstream
		}
	}
	return n, err
}
func (s *deadlineIO) writeError(err error) error {
	if err == io.ErrClosedPipe || err == io.EOF {
		s.mu.Lock()
		upstream, closed := s.writeErr, s.closed
		s.mu.Unlock()
		if upstream != nil {
			return upstream
		}
		if closed {
			return net.ErrClosed
		}
	}
	return err
}
func (s *deadlineIO) awaitAck() error {
	if !s.pendingAck {
		return nil
	}
	var ack [1]byte
	if _, err := io.ReadFull(s.write, ack[:]); err != nil {
		return s.writeError(err)
	}
	s.pendingAck = false
	return nil
}
func (s *deadlineIO) Write(p []byte) (int, error) {
	if !s.start(false) {
		return 0, net.ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.awaitAck(); err != nil {
		return 0, err
	}
	total := 0
	for len(p) > 0 {
		size := min(len(p), 32<<10)
		n, err := s.write.Write(p[:size])
		total += n
		p = p[n:]
		if n > 0 {
			s.pendingAck = true
		}
		if err != nil {
			return total, s.writeError(err)
		}
		if err := s.awaitAck(); err != nil {
			return total, err
		}
	}
	return total, nil
}
func (s *deadlineIO) SetDeadline(t time.Time) error {
	if err := s.read.SetReadDeadline(t); err != nil {
		return err
	}
	return s.write.SetDeadline(t)
}
func (s *deadlineIO) SetReadDeadline(t time.Time) error  { return s.read.SetReadDeadline(t) }
func (s *deadlineIO) SetWriteDeadline(t time.Time) error { return s.write.SetDeadline(t) }
func (s *deadlineIO) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		// Release local callers/pumps before aborting remote stream I/O. The raw H2
		// stream cancels the client request or interrupts only the server response.
		s.read.Close()
		s.readPump.Close()
		s.write.Close()
		s.writePump.Close()
		s.err = s.raw.Close()
		s.wg.Wait()
		close(s.done)
	})
	<-s.done
	return s.err
}
