package policy

import (
	"context"
	"strconv"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	storepb "github.com/agile-crypto/citius-core/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Policy is the domain representation of an access-control / algorithm policy.
type Policy struct {
	stored *storepb.StoredPolicy
}

// NewPolicy creates a Policy from explicit domain parameters.
// rulesJSON is the core representation of the policy's rules (may be nil for
// an "open" policy with no restrictions). Optional fields such as labels are
// set via functional options.
//
//	p := policy.NewPolicy("pol_01HXYZ", "default-sig-policy", rulesBytes,
//	    policy.WithLabels(map[string]string{"team": "security"}),
//	)
func NewPolicy(publicID, name string, rulesJSON []byte, opt ...Option) *Policy {
	opts := getOpts(opt...)
	sp := &storepb.StoredPolicy{
		PublicId:  publicID,
		Name:      name,
		RulesJson: rulesJSON,
		Labels:    opts.withLabels,
	}
	return &Policy{stored: sp}
}

// New wraps an existing StoredPolicy proto into the domain type.
// This is used for rehydration from storage — callers creating a new policy
// should prefer NewPolicy(publicID, name, rulesJSON, opts...) instead.
func New(stored *storepb.StoredPolicy) *Policy {
	if stored == nil {
		stored = &storepb.StoredPolicy{}
	}
	return &Policy{stored: stored}
}

// ---- Accessors ----

func (p *Policy) StoredPolicy() *storepb.StoredPolicy { return p.stored }

func (p *Policy) PublicID() string { return p.stored.GetPublicId() }

func (p *Policy) Name() string { return p.stored.GetName() }

// RulesJSON returns the raw rules_json bytes from the underlying StoredPolicy.
func (p *Policy) RulesJSON() []byte { return p.stored.GetRulesJson() }

// Version returns the policy's version: 1 when created, one more on each
// update. It is 0 when the stored policy records none (written before
// versions were kept) or records one that is not a positive integer;
// HasValidVersion tells these apart.
func (p *Policy) Version() int64 {
	v, err := strconv.ParseInt(p.stored.GetVersion(), 10, 64)
	if err != nil || v < 1 {
		return 0
	}
	return v
}

// HasValidVersion reports whether the stored version is unset or a positive
// integer, the only two states the Enforcer writes.
func (p *Policy) HasValidVersion() bool {
	return p.stored.GetVersion() == "" || p.Version() > 0
}

// CreateTime returns when the policy was created, or nil if not recorded.
func (p *Policy) CreateTime() *timestamppb.Timestamp {
	return proto.CloneOf(p.stored.GetCreateTime())
}

// UpdateTime returns when the policy was last written, or nil if not
// recorded.
func (p *Policy) UpdateTime() *timestamppb.Timestamp {
	return proto.CloneOf(p.stored.GetUpdateTime())
}

// Callers should use Clone() before mutating.
func (p *Policy) Clone() *Policy {
	return &Policy{stored: proto.Clone(p.stored).(*storepb.StoredPolicy)}
}

// VetForWrite validates the Policy.
func (p *Policy) VetForWrite(ctx context.Context, op core.WriteOp) error {
	const opVet errors.Op = "policy.(Policy).VetForWrite"
	switch op {
	case core.OpCreate, core.OpUpdate:
		if p.stored.GetPublicId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "public_id is required")
		}
		if p.stored.GetName() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "name is required")
		}
	case core.OpDelete:
		// No additional validation required for delete.
	}
	return nil
}

var _ core.VetForWriter = (*Policy)(nil)
