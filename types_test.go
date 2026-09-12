package core_test

import (
	"testing"

	core "github.com/agile-crypto/citius-core"
)

// Types tests are compile-only test to verify that the types exist and have the expected fields.

func TestKeyCreationSpec_hasRequiredFields(t *testing.T) {
	spec := core.KeyCreationSpec{
		Name:       "signing-key",
		TemplateID: "ecdsa-p256-sha256",
		PolicyID:   "pol_01HXYZ",
	}
	if spec.Name == "" {
		t.Error("Name field missing")
	}
	if spec.TemplateID == "" {
		t.Error("TemplateID field missing")
	}
	if spec.PolicyID == "" {
		t.Error("PolicyID field missing")
	}
}

func TestOperation_stringConstants(t *testing.T) {
	// Operation constants are untyped strings matching ValidateOperation's string param.
	tests := []struct {
		name string
		op   core.Operation
		want string
	}{
		{"sign", core.OperationSign, "sign"},
		{"verify", core.OperationVerify, "verify"},
		{"digest_sign", core.OperationDigestSign, "digest_sign"},
		{"digest_verify", core.OperationDigestVerify, "digest_verify"},
		{"create_key", core.OperationCreateKey, "create_key"},
	}
	for _, tt := range tests {
		if string(tt.op) != tt.want {
			t.Errorf("%s: got %q want %q", tt.name, tt.op, tt.want)
		}
	}
}

func TestKeyMaterial_hasFields(t *testing.T) {
	km := core.KeyMaterial{
		PublicKeyBytes:  []byte("pub"),
		PrivateKeyBytes: []byte("priv"),
		Algorithm:       "ecdsa-p256",
	}
	if km.Algorithm == "" {
		t.Error("Algorithm field missing")
	}
	if km.PublicKeyBytes == nil {
		t.Error("PublicKeyBytes field missing")
	}
	if km.PrivateKeyBytes == nil {
		t.Error("PrivateKeyBytes field missing")
	}
}
