package connectip

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestParseVarint(t *testing.T) {
	for _, tc := range []uint64{0, 1, 63, 64, 16383, 16384, 1_073_741_823} {
		enc := quicvarint.Append(nil, tc)
		v, n, ok := parseVarint(enc)
		require.True(t, ok)
		require.Equal(t, tc, v)
		require.Equal(t, len(enc), n)
	}
}

func TestH2DatagramStreamSendDatagram(t *testing.T) {
	body := newH2RequestBody()
	stream := &h2DatagramStream{
		requestBody:  body,
		responseBody: io.NopCloser(bytes.NewReader(nil)),
	}

	payload := []byte{0x45, 0x00, 0x00, 0x14}
	datagram := append(append([]byte{}, contextIDZero...), payload...)
	require.NoError(t, stream.SendDatagram(datagram))
	stream.requestBody.closeWrite()

	buf, err := io.ReadAll(body)
	require.NoError(t, err)
	capType, capPayload, consumed, ok, err := parseCapsule(buf)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, len(buf), consumed)
	require.Equal(t, h2DatagramCapsuleType, capType)
	require.Equal(t, payload, capPayload)
}

// Capsules sent while the transport is busy are handed over in one read, which
// is one DATA frame and one write to the connection instead of one per packet.
func TestH2RequestBodyCoalesces(t *testing.T) {
	body := newH2RequestBody()
	for i := range 5 {
		require.NoError(t, body.writeCapsule(h2DatagramCapsuleType, []byte{byte(i), 1, 2, 3}))
	}
	buf := make([]byte, 16<<10)
	n, err := body.Read(buf)
	require.NoError(t, err)
	got := buf[:n]
	for i := range 5 {
		capType, payload, consumed, ok, err := parseCapsule(got)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, h2DatagramCapsuleType, capType)
		require.Equal(t, []byte{byte(i), 1, 2, 3}, payload)
		got = got[consumed:]
	}
	require.Empty(t, got)
}

// A sender is held back once a frame's worth is waiting, and let through as
// soon as the transport takes it.
func TestH2RequestBodyBackpressure(t *testing.T) {
	body := newH2RequestBody()
	packet := make([]byte, 1280)
	for body.queued()+1284 <= h2RequestBodyLimit {
		require.NoError(t, body.writeCapsule(h2DatagramCapsuleType, packet))
	}
	sent := make(chan error, 1)
	go func() { sent <- body.writeCapsule(h2DatagramCapsuleType, packet) }()
	select {
	case <-sent:
		t.Fatal("a full queue accepted another capsule")
	case <-time.After(50 * time.Millisecond):
	}
	_, err := body.Read(make([]byte, 64<<10))
	require.NoError(t, err)
	select {
	case err := <-sent:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("the sender stayed blocked after the queue was drained")
	}
}

// Closing the stream lets the transport drain what is queued and then ends
// the body; the transport closing the body releases a blocked sender.
func TestH2RequestBodyClose(t *testing.T) {
	body := newH2RequestBody()
	require.NoError(t, body.writeCapsule(h2DatagramCapsuleType, []byte{1}))
	body.closeWrite()
	require.Error(t, body.writeCapsule(h2DatagramCapsuleType, []byte{2}))
	n, err := body.Read(make([]byte, 64))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	_, err = body.Read(make([]byte, 64))
	require.ErrorIs(t, err, io.EOF)

	body = newH2RequestBody()
	big := make([]byte, h2RequestBodyLimit)
	require.NoError(t, body.writeCapsule(h2DatagramCapsuleType, big))
	sent := make(chan error, 1)
	go func() { sent <- body.writeCapsule(h2DatagramCapsuleType, []byte{1}) }()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, body.Close())
	select {
	case err := <-sent:
		require.ErrorIs(t, err, io.ErrClosedPipe)
	case <-time.After(time.Second):
		t.Fatal("closing the body did not release the sender")
	}
}

func TestH2DatagramStreamReceiveDatagram(t *testing.T) {
	nonDatagramCapsule := buildCapsule(7, []byte("ignore"))
	payload := []byte{0x60, 0x00, 0x00, 0x00}
	datagramCapsule := buildCapsule(h2DatagramCapsuleType, payload)

	stream := &h2DatagramStream{
		requestBody:  newH2RequestBody(),
		responseBody: io.NopCloser(bytes.NewReader(append(nonDatagramCapsule, datagramCapsule...))),
	}

	got, err := stream.ReceiveDatagram(context.Background())
	require.NoError(t, err)
	require.Equal(t, append(append([]byte{}, contextIDZero...), payload...), got)
}

// Capsules arrive cut at arbitrary points, and some are larger than the
// buffer; every one still comes out whole and in order.
func TestH2DatagramStreamReceiveAcrossReads(t *testing.T) {
	var stream []byte
	var want [][]byte
	for i := range 200 {
		size := 1 + (i*97)%1400
		if i == 150 {
			size = 3 * h2ReceiveBufferSize
		}
		payload := bytes.Repeat([]byte{byte(i)}, size)
		want = append(want, payload)
		stream = append(stream, buildCapsule(h2DatagramCapsuleType, payload)...)
	}
	s := &h2DatagramStream{
		requestBody:  newH2RequestBody(),
		responseBody: io.NopCloser(&choppyReader{data: stream}),
	}
	for i, payload := range want {
		got, err := s.ReceiveDatagram(context.Background())
		require.NoError(t, err, "datagram %d", i)
		require.Equal(t, append(append([]byte{}, contextIDZero...), payload...), got, "datagram %d", i)
	}
	_, err := s.ReceiveDatagram(context.Background())
	require.ErrorIs(t, err, io.EOF)
}

// choppyReader returns its data in pieces of varying, awkward sizes.
type choppyReader struct {
	data []byte
	n    int
}

func (r *choppyReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	r.n++
	size := min(len(p), len(r.data), 1+(r.n*7919)%5000)
	copy(p, r.data[:size])
	r.data = r.data[size:]
	return size, nil
}

func buildCapsule(capsuleType uint64, payload []byte) []byte {
	buf := make([]byte, 0, 16+len(payload))
	buf = quicvarint.Append(buf, capsuleType)
	buf = quicvarint.Append(buf, uint64(len(payload)))
	buf = append(buf, payload...)
	return buf
}

// queued reports how many bytes wait for the transport.
func (b *h2RequestBody) queued() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}
