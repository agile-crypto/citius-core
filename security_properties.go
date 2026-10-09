package core

import types "github.com/agile-crypto/citius-api-go/gen/go/types"

// SecurityProperties mirrors [types.UniversalSecurityProperties]. On a
// request they are minimums the template must meet; on a template, what it
// provides.
//
// QuantumSafe and FipsApproved keep the proto's presence: nil means not
// stated, which is not the same as false. A request that states neither
// does not require them, and a template or key that does not state them is
// not claiming to lack them.
type SecurityProperties struct {
	SecurityStrength uint32
	SecurityLevel    types.NistSecurityLevel
	QuantumSafe      *bool
	NistStatus       types.NistStatus
	FipsApproved     *bool
}

func (s *SecurityProperties) ToProto() *types.UniversalSecurityProperties {
	if s == nil {
		return nil
	}
	return &types.UniversalSecurityProperties{
		SecurityStrengthBits: s.SecurityStrength,
		NistSecurityLevel:    s.SecurityLevel,
		QuantumSafe:          cloneBool(s.QuantumSafe),
		NistStatus:           s.NistStatus,
		FipsApproved:         cloneBool(s.FipsApproved),
	}
}

func SecurityPropertiesFromProto(s *types.UniversalSecurityProperties) *SecurityProperties {
	if s == nil {
		return nil
	}
	return &SecurityProperties{
		SecurityStrength: s.GetSecurityStrengthBits(),
		SecurityLevel:    s.GetNistSecurityLevel(),
		QuantumSafe:      cloneBool(s.QuantumSafe),
		NistStatus:       s.GetNistStatus(),
		FipsApproved:     cloneBool(s.FipsApproved),
	}
}

// IsTrue reports whether an optional property is stated and true.
func IsTrue(b *bool) bool {
	return b != nil && *b
}

// cloneBool copies an optional property, so a converted value never aliases
// the one it was converted from.
func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// boolPtr returns a pointer to a copy of b.
func boolPtr(b bool) *bool {
	return &b
}
