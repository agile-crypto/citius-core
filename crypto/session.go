package crypto

import (
	storepb "github.com/agile-crypto/citius-core/store"
	"google.golang.org/protobuf/proto"
)

// Session is the domain representation of a multi-part streaming session.
type Session struct {
	stored *storepb.StoredSession
}

// NewSession wraps a StoredSession.
func NewSession(stored *storepb.StoredSession) *Session {
	if stored == nil {
		stored = &storepb.StoredSession{}
	}
	return &Session{stored: stored}
}

// StoredSession returns the embedded proto.
func (s *Session) StoredSession() *storepb.StoredSession { return s.stored }

func (s *Session) Clone() *Session {
	return &Session{stored: proto.Clone(s.stored).(*storepb.StoredSession)}
}
