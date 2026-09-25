package template_test

import (
	"context"
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/template"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// MatchesScope Tests
// ============================================================================

func TestMatchesScope_tabledriven(t *testing.T) {
	tests := []struct {
		name  string
		tmpl  *template.Template
		scope core.ScopeSpecification
		want  bool
	}{
		{
			name: "exact scope match - signature standard",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
			},
			want: true,
		},
		{
			name: "no match - wrong scope variant",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignaturePrehashed,
			},
			want: false,
		},
		{
			name: "no match - wrong primitive",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpecification{
				Scope: core.ScopeAeadStandard,
			},
			want: false,
		},
		{
			name: "zero scope - matches all (no scope filter)",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpecification{},
			want:  true,
		},
		{
			name: "template has multiple scopes - one matches",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{
					{
						Scope: &api.ScopeSpecification{
							ScopeSpec: &api.ScopeSpecification_Signature{
								Signature: &api.SignatureScopeSpec{
									Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
								},
							},
						},
					},
					{
						Scope: &api.ScopeSpecification{
							ScopeSpec: &api.ScopeSpecification_Signature{
								Signature: &api.SignatureScopeSpec{
									Scope: api.SignatureScope_SIGNATURE_SCOPE_PREHASHED,
								},
							},
						},
					},
				},
			}),
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignaturePrehashed,
			},
			want: true,
		},
		{
			name: "template has no scopes - never matches",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{},
			}),
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignaturePrehashed,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := template.MatchesScope(ctx, tt.tmpl, &tt.scope)
			require.NoError(t, err)
			if got != tt.want {
				t.Errorf("MatchesScope(%v) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

// ============================================================================
// MatchesScope — Security Filter Tests
// ============================================================================

func boolPtr(v bool) *bool { return &v }

func TestMatchesScope_securityFilters_tabledriven(t *testing.T) {
	// ECDSA template: fips_approved=true, quantum_safe=false
	ecdsaTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ecdsa-p256-sha256",
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
						Security: &api.UniversalSecurityProperties{
							FipsApproved: boolPtr(true),
							QuantumSafe:  boolPtr(false),
						},
					},
				},
			},
		}},
	})

	// ML-DSA template: quantum_safe=true, fips_approved=false
	mldsaTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ml-dsa-65",
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
						Security: &api.UniversalSecurityProperties{
							QuantumSafe:  boolPtr(true),
							FipsApproved: boolPtr(false),
						},
					},
				},
			},
		}},
	})

	// Bare template: no security properties in scope
	bareTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "bare-sig",
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
		}},
	})

	tests := []struct {
		name  string
		tmpl  *template.Template
		scope core.ScopeSpecification
		want  bool
	}{
		{
			name: "fips_approved=true matches ecdsa",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
				SecurityProps: &core.SecurityProperties{
					FipsApproved: true,
				},
			},
			want: true,
		},
		{
			name: "fips_approved=true does not match mldsa",
			tmpl: mldsaTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
				SecurityProps: &core.SecurityProperties{
					FipsApproved: true,
				},
			},
			want: false,
		},
		{
			name: "quantum_safe=true matches mldsa",
			tmpl: mldsaTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
				SecurityProps: &core.SecurityProperties{
					QuantumSafe: true,
				},
			},
			want: true,
		},
		{
			name: "quantum_safe=true does not match ecdsa",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
				SecurityProps: &core.SecurityProperties{
					QuantumSafe: true,
				},
			},
			want: false,
		},
		{
			name: "both fips and quantum_safe required - no template satisfies both",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
				SecurityProps: &core.SecurityProperties{
					FipsApproved: true,
					QuantumSafe:  true,
				},
			},
			want: false,
		},
		{
			name: "no security filter - scope only - matches any",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
			},
			want: true,
		},
		{
			name: "bare template (nil security) fails fips filter",
			tmpl: bareTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
				SecurityProps: &core.SecurityProperties{
					FipsApproved: true,
				},
			},
			want: false,
		},
		{
			name: "bare template (nil security) passes without security filter",
			tmpl: bareTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
			},
			want: true,
		},
		{
			name: "fips_approved=false explicitly matches mldsa",
			tmpl: mldsaTmpl,
			scope: core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
				SecurityProps: &core.SecurityProperties{
					FipsApproved: false,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := template.MatchesScope(ctx, tt.tmpl, &tt.scope)
			require.NoError(t, err)
			if got != tt.want {
				t.Errorf("MatchesScope(%v) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestSupportsOperation(t *testing.T) {
	ctx := context.Background()
	tmpl := template.NewTemplate(&api.TemplateInfo{
		ScopedCapabilities: []*api.ScopedCapabilities{
			{
				Scope: &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD},
				}},
				Operations: []api.CryptoOperation{api.CryptoOperation_CRYPTO_OPERATION_SIGN},
			},
			{
				Scope: &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{Scope: api.SignatureScope_SIGNATURE_SCOPE_PREHASHED},
				}},
				Operations: []api.CryptoOperation{api.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN},
			},
		},
	})
	tests := []struct {
		scope     core.Scope
		operation api.CryptoOperation
		want      bool
	}{
		{core.ScopeSignatureStandard, api.CryptoOperation_CRYPTO_OPERATION_SIGN, true},
		{core.ScopeSignatureStandard, api.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN, false},
		{core.ScopeSignaturePrehashed, api.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN, true},
		{core.ScopeSignaturePrehashed, api.CryptoOperation_CRYPTO_OPERATION_SIGN, false},
		{core.ScopeSignatureWithContext, api.CryptoOperation_CRYPTO_OPERATION_SIGN, false},
	}
	for _, tt := range tests {
		got, err := template.SupportsOperation(ctx, tmpl, tt.scope, tt.operation)
		require.NoError(t, err)
		require.Equal(t, tt.want, got, "%s/%s", tt.scope, tt.operation)
	}
}
