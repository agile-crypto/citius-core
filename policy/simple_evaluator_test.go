package policy

import (
	"testing"

	core "github.com/agile-crypto/citius-core"
)

func newSimple() *SimpleRulesEvaluator {
	return NewSimpleRulesEvaluator()
}

// ============================================================================
// Validate
// ============================================================================

func TestSimple_Validate_emptyBytes_ok(t *testing.T) {
	if err := newSimple().Validate(nil); err != nil {
		t.Errorf("Validate(nil): %v", err)
	}
}

func TestSimple_Validate_validJSON_ok(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_templates":["ecdsa-p256-sha256"]}`)
	if err := newSimple().Validate(raw); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestSimple_Validate_invalidJSON_error(t *testing.T) {
	if err := newSimple().Validate([]byte(`{broken`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSimple_Validate_unknownOperation_error(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_operations":{"key_operations":["teleport"]}}`)
	if err := newSimple().Validate(raw); err == nil {
		t.Fatal("expected error for unknown operation")
	}
}

// ============================================================================
// AllowsOperation
// ============================================================================

func TestSimple_AllowsOperation_noRules_denyAll(t *testing.T) {
	ok, err := newSimple().AllowsOperation(nil, core.OperationSign)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny when rules are empty (deny-by-default)")
	}
}

func TestSimple_AllowsOperation_absentSection_denyAll(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_templates":["x"]}`)
	ok, err := newSimple().AllowsOperation(raw, core.OperationSign)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny when allowed_operations is absent (deny-by-default)")
	}
}

func TestSimple_AllowsOperation_inList_allowed(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_operations":{"key_operations":["sign","verify"]}}`)
	ok, err := newSimple().AllowsOperation(raw, core.OperationSign)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !ok {
		t.Error("expected allow for 'sign' in list")
	}
}

func TestSimple_AllowsOperation_notInList_denied(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_operations":{"key_operations":["sign","verify"]}}`)
	ok, err := newSimple().AllowsOperation(raw, core.OperationEncrypt)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny for 'encrypt' not in list")
	}
}

func TestSimple_AllowsOperation_emptyKeyOps_denyAll(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_operations":{"key_operations":[]}}`)
	ok, err := newSimple().AllowsOperation(raw, core.OperationSign)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny when key_operations is empty []")
	}
}

// ============================================================================
// AllowsTemplate
// ============================================================================

func TestSimple_AllowsTemplate_noRules_denyAll(t *testing.T) {
	ok, err := newSimple().AllowsTemplate(nil, "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny when rules are empty (deny-by-default)")
	}
}

func TestSimple_AllowsTemplate_absentSection_denyAll(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_operations":{"key_operations":["sign"]}}`)
	ok, err := newSimple().AllowsTemplate(raw, "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny when allowed_templates is absent (deny-by-default)")
	}
}

func TestSimple_AllowsTemplate_inList_allowed(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_templates":["ecdsa-p256-sha256","ml-dsa-65"]}`)
	ok, err := newSimple().AllowsTemplate(raw, "ml-dsa-65")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !ok {
		t.Error("expected allow for template in list")
	}
}

func TestSimple_AllowsTemplate_notInList_denied(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_templates":["ecdsa-p256-sha256"]}`)
	ok, err := newSimple().AllowsTemplate(raw, "aes-256-gcm")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny for template not in list")
	}
}

func TestSimple_AllowsTemplate_emptyList_denyAll(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_templates":[]}`)
	ok, err := newSimple().AllowsTemplate(raw, "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ok {
		t.Error("expected deny when allowed_templates is empty []")
	}
}

// ============================================================================
// MeetsSecurityRequirements
// ============================================================================

func TestSimple_MeetsSecurity_noRules_ok(t *testing.T) {
	info := TemplateSecurityInfo{TemplateID: "x", FIPSApproved: false}
	if err := newSimple().MeetsSecurityRequirements(nil, info); err != nil {
		t.Errorf("error: %v", err)
	}
}

func TestSimple_MeetsSecurity_fipsRequired_templateFips_ok(t *testing.T) {
	raw := []byte(`{"version":"1","security_requirements":{"fips_approved":true}}`)
	info := TemplateSecurityInfo{TemplateID: "x", FIPSApproved: true}
	if err := newSimple().MeetsSecurityRequirements(raw, info); err != nil {
		t.Errorf("error: %v", err)
	}
}

func TestSimple_MeetsSecurity_fipsRequired_templateNotFips_denied(t *testing.T) {
	raw := []byte(`{"version":"1","security_requirements":{"fips_approved":true}}`)
	info := TemplateSecurityInfo{TemplateID: "chacha20", FIPSApproved: false}
	if err := newSimple().MeetsSecurityRequirements(raw, info); err == nil {
		t.Fatal("expected denial: fips_approved required but template is not FIPS")
	}
}

func TestSimple_MeetsSecurity_blockDeprecated_activeTemplate_ok(t *testing.T) {
	raw := []byte(`{"version":"1","security_requirements":{"block_deprecated":true}}`)
	info := TemplateSecurityInfo{TemplateID: "x", TemplateStatus: "active"}
	if err := newSimple().MeetsSecurityRequirements(raw, info); err != nil {
		t.Errorf("error: %v", err)
	}
}

func TestSimple_MeetsSecurity_blockDeprecated_deprecatedTemplate_denied(t *testing.T) {
	raw := []byte(`{"version":"1","security_requirements":{"block_deprecated":true}}`)
	info := TemplateSecurityInfo{TemplateID: "3des", TemplateStatus: "deprecated"}
	if err := newSimple().MeetsSecurityRequirements(raw, info); err == nil {
		t.Fatal("expected denial: block_deprecated is true and template is deprecated")
	}
}

func TestSimple_MeetsSecurity_blockDeprecated_forbiddenTemplate_denied(t *testing.T) {
	raw := []byte(`{"version":"1","security_requirements":{"block_deprecated":true}}`)
	info := TemplateSecurityInfo{TemplateID: "rc4", TemplateStatus: "forbidden"}
	if err := newSimple().MeetsSecurityRequirements(raw, info); err == nil {
		t.Fatal("expected denial: block_deprecated is true and template is forbidden")
	}
}

func TestSimple_MeetsSecurity_fipsAndBlockDeprecated_both(t *testing.T) {
	raw := []byte(`{"version":"1","security_requirements":{"fips_approved":true,"block_deprecated":true}}`)
	info := TemplateSecurityInfo{TemplateID: "x", FIPSApproved: true, TemplateStatus: "active"}
	if err := newSimple().MeetsSecurityRequirements(raw, info); err != nil {
		t.Errorf("error: %v", err)
	}
}

// ============================================================================
// AllowedTemplateIDs
// ============================================================================

func TestSimple_AllowedTemplateIDs_noRules_emptySlice(t *testing.T) {
	ids, err := newSimple().AllowedTemplateIDs(nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ids == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(ids) != 0 {
		t.Errorf("expected 0, got %d", len(ids))
	}
}

func TestSimple_AllowedTemplateIDs_absentSection_emptySlice(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_operations":{"key_operations":["sign"]}}`)
	ids, err := newSimple().AllowedTemplateIDs(raw)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ids == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(ids) != 0 {
		t.Errorf("expected 0, got %d", len(ids))
	}
}

func TestSimple_AllowedTemplateIDs_presentSection_returnsSlice(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_templates":["ecdsa-p256-sha256","ml-dsa-65"]}`)
	ids, err := newSimple().AllowedTemplateIDs(raw)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}
}

func TestSimple_AllowedTemplateIDs_emptySection_emptySlice(t *testing.T) {
	raw := []byte(`{"version":"1","allowed_templates":[]}`)
	ids, err := newSimple().AllowedTemplateIDs(raw)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ids == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(ids) != 0 {
		t.Errorf("expected 0, got %d", len(ids))
	}
}

// ============================================================================
// ProviderRequirements
// ============================================================================

func TestSimple_ProviderRequirements(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		want  core.ProviderRequirements
	}{
		{"no rules", "", core.ProviderRequirements{}},
		{"absent section", `{"version":"1","allowed_templates":["ml-dsa-65"]}`, core.ProviderRequirements{}},
		{"empty section", `{"version":"1","provider_requirements":{}}`, core.ProviderRequirements{}},
		{"memory safe", `{"version":"1","provider_requirements":{"memory_safe":true}}`, core.ProviderRequirements{MemorySafe: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newSimple().ProviderRequirements([]byte(tt.rules))
			if err != nil {
				t.Fatalf("ProviderRequirements: %v", err)
			}
			if got != tt.want {
				t.Errorf("ProviderRequirements = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSimple_ProviderRequirements_unreadableSection_errors(t *testing.T) {
	_, err := newSimple().ProviderRequirements([]byte(`{"version":"1","provider_requirements":{"fips140":true}}`))
	if err == nil {
		t.Fatal("expected an error for a section with an unknown requirement")
	}
}

func TestNoop_ProviderRequirements_requiresNothing(t *testing.T) {
	got, err := NewNoopEvaluator().ProviderRequirements([]byte(`{"provider_requirements":{"memory_safe":true}}`))
	if err != nil || !got.IsZero() {
		t.Errorf("ProviderRequirements = %+v, %v; want zero, nil", got, err)
	}
}
