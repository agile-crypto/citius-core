package core

import types "github.com/agile-crypto/citius-api-go/gen/go/types"

type SecurityProperties struct {
	SecurityStrength uint32
	SecurityLevel    types.NistSecurityLevel
	QuantumSafe      bool
	NistStatus       types.NistStatus
	FipsApproved     bool
}

func (s *SecurityProperties) ToProto() *types.UniversalSecurityProperties {
	if s == nil {
		return nil
	}
	return &types.UniversalSecurityProperties{
		SecurityStrengthBits: s.SecurityStrength,
		NistSecurityLevel:    s.SecurityLevel,
		QuantumSafe:          &s.QuantumSafe,
		NistStatus:           s.NistStatus,
		FipsApproved:         &s.FipsApproved,
	}
}

func SecurityPropertiesFromProto(s *types.UniversalSecurityProperties) *SecurityProperties {
	if s == nil {
		return nil
	}
	derefBool := func(b *bool) bool {
		if b == nil {
			return false
		}
		return *b
	}
	return &SecurityProperties{
		SecurityStrength: s.SecurityStrengthBits,
		SecurityLevel:    s.NistSecurityLevel,
		QuantumSafe:      derefBool(s.QuantumSafe),
		NistStatus:       s.NistStatus,
		FipsApproved:     derefBool(s.FipsApproved),
	}
}
