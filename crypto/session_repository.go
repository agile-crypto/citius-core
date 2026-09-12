package crypto

import "context"

// SessionRepository defines the persistence contract for multi-part sessions.
type SessionRepository interface {
	PutSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	ListSessions(ctx context.Context) ([]string, error)
}
