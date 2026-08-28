package connectip

import (
	"io"

	"github.com/quic-go/quic-go/http3"
)

// parseCapsuleReader reads a single capsule from r.
//
// quic-go 0.61 replaced the stateless http3.ParseCapsule with the stateful
// http3.CapsuleParser. Callers that read a standalone capsule keep the old
// semantics by using a parser instance per capsule; the connection read loop
// uses a long lived parser instead, which additionally rejects capsules that
// were not fully consumed.
func parseCapsuleReader(r io.Reader) (http3.CapsuleType, http3.CapsuleReader, error) {
	return http3.NewCapsuleParser(r).Next()
}
