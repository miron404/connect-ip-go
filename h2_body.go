package connectip

import (
	"io"
	"sync"

	"github.com/quic-go/quic-go/quicvarint"
)

// h2RequestBodyLimit is how much may wait for the HTTP/2 transport before a
// sender is held back. A little over one frame at the default frame size: the
// transport takes a whole frame per read, and holding more would only queue
// packets behind a congested connection.
const h2RequestBodyLimit = 16<<10 + 2048

// h2RequestBody is the request body the tunnel's capsules are sent through.
//
// The HTTP/2 client writes one DATA frame, and flushes it to the connection,
// for every read it makes from a request body. Through an io.Pipe every read
// is one packet, so each packet cost a frame, a TLS record and a write system
// call of its own, which made the HTTP/2 mode spend most of its time in the
// kernel. Here capsules gather while the transport is busy with the previous
// write, and the next read takes all of them at once. A packet sent while the
// transport is idle still goes out immediately, so nothing waits on a timer.
type h2RequestBody struct {
	mu       sync.Mutex
	readable *sync.Cond
	writable *sync.Cond
	pending  []byte
	// readErr is what the transport gets once pending is drained: io.EOF
	// when the tunnel closes the stream. writeErr is what a sender gets: the
	// transport closing the body ends the request, and nothing is sent after.
	readErr, writeErr error
}

func newH2RequestBody() *h2RequestBody {
	b := &h2RequestBody{pending: make([]byte, 0, h2RequestBodyLimit)}
	b.readable = sync.NewCond(&b.mu)
	b.writable = sync.NewCond(&b.mu)
	return b
}

// writeCapsule queues one capsule, waiting while the queue is full. A capsule
// is always accepted into an empty queue, whatever its size.
func (b *h2RequestBody) writeCapsule(capsuleType uint64, payload []byte) error {
	size := quicvarint.Len(capsuleType) + quicvarint.Len(uint64(len(payload))) + len(payload)
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.writeErr == nil && len(b.pending) > 0 && len(b.pending)+size > h2RequestBodyLimit {
		b.writable.Wait()
	}
	if b.writeErr != nil {
		return b.writeErr
	}
	b.pending = quicvarint.Append(b.pending, capsuleType)
	b.pending = quicvarint.Append(b.pending, uint64(len(payload)))
	b.pending = append(b.pending, payload...)
	b.readable.Signal()
	return nil
}

// Read hands the transport everything queued, up to len(p).
func (b *h2RequestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.pending) == 0 && b.readErr == nil {
		b.readable.Wait()
	}
	if len(b.pending) == 0 {
		return 0, b.readErr
	}
	n := copy(p, b.pending)
	b.pending = b.pending[:copy(b.pending, b.pending[n:])]
	b.writable.Broadcast()
	return n, nil
}

// Close is called by the transport when it is done with the body, and turns
// away every sender from then on.
func (b *h2RequestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writeErr == nil {
		b.writeErr = io.ErrClosedPipe
	}
	if b.readErr == nil {
		b.readErr = io.ErrClosedPipe
	}
	b.pending = b.pending[:0]
	b.readable.Broadcast()
	b.writable.Broadcast()
	return nil
}

// closeWrite ends the stream from the tunnel's side: the transport reads what
// is queued, then io.EOF.
func (b *h2RequestBody) closeWrite() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writeErr == nil {
		b.writeErr = io.ErrClosedPipe
	}
	if b.readErr == nil {
		b.readErr = io.EOF
	}
	b.readable.Broadcast()
	b.writable.Broadcast()
}
