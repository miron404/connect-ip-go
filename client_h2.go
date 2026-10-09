package connectip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
)

const h2DatagramCapsuleType uint64 = 0

// DialH2 dials a proxied connection over HTTP/2 CONNECT-IP.
//
// This transport carries proxied packets inside HTTP capsule DATAGRAM frames.
func DialH2(ctx context.Context, client *http.Client, template *uritemplate.Template, additionalHeaders http.Header) (*Conn, *http.Response, error) {
	if len(template.Varnames()) > 0 {
		return nil, nil, errors.New("connect-ip: IP flow forwarding not supported")
	}

	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	body := newH2RequestBody()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, u.String(), body)
	if err != nil {
		_ = body.Close()
		return nil, nil, fmt.Errorf("connect-ip: failed to create request: %w", err)
	}
	req.Host = authorityFromURL(u)
	req.ContentLength = -1
	req.Header = make(http.Header)
	for k, v := range additionalHeaders {
		req.Header[k] = v
	}

	rsp, err := client.Do(req)
	if err != nil {
		_ = body.Close()
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		_ = body.Close()
		_ = rsp.Body.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}

	stream := &h2DatagramStream{
		requestBody:  body,
		responseBody: rsp.Body,
	}
	return newDatagramOnlyConn(stream), rsp, nil
}

func authorityFromURL(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	host := u.Hostname()
	if host == "" {
		return u.Host
	}
	return host + ":443"
}

type h2DatagramStream struct {
	requestBody  *h2RequestBody
	responseBody io.ReadCloser

	readMu sync.Mutex
	// recvBuf[recvStart:recvEnd] is what has been read and not yet parsed.
	recvBuf            []byte
	recvStart, recvEnd int
}

// h2ReceiveBufferSize holds a whole HTTP/2 DATA frame at the default frame
// size, so a frame carrying several capsules is taken in one read.
const h2ReceiveBufferSize = 16 << 10

// ReceiveDatagram returns the next datagram, backed by the receive buffer. It
// is valid until the next call, as ReadPacketZeroCopy documents.
func (s *h2DatagramStream) ReceiveDatagram(_ context.Context) ([]byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.recvBuf == nil {
		s.recvBuf = make([]byte, h2ReceiveBufferSize)
	}
	for {
		pending := s.recvBuf[s.recvStart:s.recvEnd]
		capsuleType, payload, consumed, ok, err := parseCapsule(pending)
		if err != nil {
			return nil, err
		}
		if ok {
			s.recvStart += consumed
			if capsuleType != h2DatagramCapsuleType {
				continue
			}
			payloadOffset := consumed - len(payload)
			if payloadOffset < len(contextIDZero) {
				return nil, errors.New("connect-ip: malformed datagram capsule")
			}
			// The capsule header in front of the payload is overwritten
			// with the context ID, so the datagram needs no copy.
			copy(pending[payloadOffset-len(contextIDZero):payloadOffset], contextIDZero)
			return pending[payloadOffset-len(contextIDZero) : consumed], nil
		}

		// Read straight into the buffer rather than through a fresh one per
		// call. Once the end is reached, the partial capsule left over moves
		// to the front, which may overwrite the datagram returned last time;
		// the caller is done with it by now. Only a capsule larger than the
		// whole buffer makes it grow.
		if s.recvEnd == len(s.recvBuf) {
			if s.recvStart == 0 {
				grown := make([]byte, 2*len(s.recvBuf))
				copy(grown, s.recvBuf)
				s.recvBuf = grown
			} else {
				s.recvEnd = copy(s.recvBuf, pending)
				s.recvStart = 0
			}
		}
		n, readErr := s.responseBody.Read(s.recvBuf[s.recvEnd:])
		s.recvEnd += n
		if n > 0 {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func (s *h2DatagramStream) SendDatagram(data []byte) error {
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return fmt.Errorf("connect-ip: malformed datagram: %w", err)
	}
	if contextID != 0 {
		return fmt.Errorf("connect-ip: unsupported datagram context ID: %d", contextID)
	}
	if err := s.requestBody.writeCapsule(h2DatagramCapsuleType, data[n:]); err != nil {
		return fmt.Errorf("connect-ip: failed to send datagram capsule: %w", err)
	}
	return nil
}

func (s *h2DatagramStream) CancelRead(quic.StreamErrorCode) {}

func (s *h2DatagramStream) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (s *h2DatagramStream) Write(_ []byte) (int, error) {
	return 0, errors.New("connect-ip: control capsules are not supported by this transport")
}

func (s *h2DatagramStream) Close() error {
	s.requestBody.closeWrite()
	return s.responseBody.Close()
}

func parseCapsule(buf []byte) (capsuleType uint64, payload []byte, consumed int, ok bool, err error) {
	capsuleType, typeLen, ok := parseVarint(buf)
	if !ok {
		return 0, nil, 0, false, nil
	}
	payloadLen, payloadLenLen, ok := parseVarint(buf[typeLen:])
	if !ok {
		return 0, nil, 0, false, nil
	}
	headerLen := typeLen + payloadLenLen
	totalLen := headerLen + int(payloadLen)
	if totalLen < headerLen {
		return 0, nil, 0, false, errors.New("connect-ip: malformed capsule length")
	}
	if len(buf) < totalLen {
		return 0, nil, 0, false, nil
	}
	return capsuleType, buf[headerLen:totalLen], totalLen, true, nil
}

func parseVarint(buf []byte) (v uint64, n int, ok bool) {
	if len(buf) == 0 {
		return 0, 0, false
	}
	prefix := buf[0] >> 6
	n = 1 << prefix
	if len(buf) < n {
		return 0, 0, false
	}
	v = uint64(buf[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = (v << 8) | uint64(buf[i])
	}
	return v, n, true
}
