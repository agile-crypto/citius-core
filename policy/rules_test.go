package policy

import (
	"testing"

	core "github.com/agile-crypto/citius-core"
)

// ============================================================================
// ParseRules Tests
// ============================================================================

func TestParseRules_emptyBytes_returnsEmptyRules(t *testing.T) {
	// nil or empty bytes => empty Rules (all sections nil, version empty)
	rules, err := ParseRules(nil)
	if err != nil {
		t.Fatalf("ParseRules(nil): %v", err)
	}
	if rules.Version != "" {
		t.Errorf("expected empty version, got %q", rules.Version)
	}
	if rules.AllowedTemplates != nil {
		t.Errorf("expected nil AllowedTemplates, got %v", rules.AllowedTemplates)
	}
}

func TestParseRules_emptyJSON_returnsEmptyRules(t *testing.T) {
	rules, err := ParseRules([]byte(`{}`))
	if err != nil {
		t.Fatalf("ParseRules({}): %v", err)
	}
	if rules.AllowedOperations != nil {
		t.Error("expected nil AllowedOperations")
	}
}

func TestParseRules_validM1Policy(t *testing.T) {
	raw := []byte(`{
		"version": "1",
		"allowed_templates": ["ecdsa-p256-sha256", "ml-dsa-65"],
		"allowed_operations": {
			"key_operations": ["sign", "verify", "rotate_key"]
		},
		"security_requirements": {
			"fips_approved": true,
			"block_deprecated": true
		}
	}`)
	rules, err := ParseRules(raw)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if rules.Version != "1" {
		t.Errorf("Version: got %q want %q", rules.Version, "1")
	}
	if len(rules.AllowedTemplates) != 2 {
		t.Errorf("AllowedTemplates: got %d want 2", len(rules.AllowedTemplates))
	}
	if rules.AllowedOperations == nil {
		t.Fatal("AllowedOperations is nil")
	}
	if len(rules.AllowedOperations.KeyOperations) != 3 {
		t.Errorf("KeyOperations: got %d want 3", len(rules.AllowedOperations.KeyOperations))
	}
	if rules.SecurityRequirements == nil {
		t.Fatal("SecurityRequirements is nil")
	}
	if rules.SecurityRequirements.FIPSApproved == nil || !*rules.SecurityRequirements.FIPSApproved {
		t.Error("FIPSApproved: expected true")
	}
	if rules.SecurityRequirements.BlockDeprecated == nil || !*rules.SecurityRequirements.BlockDeprecated {
		t.Error("BlockDeprecated: expected true")
	}
}

func TestParseRules_invalidJSON_returnsError(t *testing.T) {
	_, err := ParseRules([]byte(`{not json}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseRules_unknownFieldsRejected(t *testing.T) {
	// A misspelt section or rule must not be silently unenforced.
	for name, raw := range map[string]string{
		"unknown section":  `{"version": "1", "future_section": {"foo": "bar"}}`,
		"misspelt section": `{"version": "1", "providerRequirements": {"memory_safe": true}}`,
		"unknown rule":     `{"version": "1", "allowed_operations": {"key_ops": ["sign"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRules([]byte(raw)); err == nil {
				t.Fatal("ParseRules: expected an error for an unknown field")
			}
		})
	}
}

// ============================================================================
// Validate Tests
// ============================================================================

func TestValidate_emptyRules_ok(t *testing.T) {
	rules := &Rules{}
	if err := rules.Validate(); err != nil {
		t.Errorf("Validate empty rules: %v", err)
	}
}

func TestValidate_validOperations_ok(t *testing.T) {
	rules := &Rules{
		Version: "1",
		AllowedOperations: &OperationRule{
			KeyOperations: []string{"sign", "verify", "encrypt", "decrypt"},
		},
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestValidate_unknownOperation_error(t *testing.T) {
	rules := &Rules{
		Version: "1",
		AllowedOperations: &OperationRule{
			KeyOperations: []string{"sign", "teleport"}, // "teleport" is not a known operation
		},
	}
	if err := rules.Validate(); err == nil {
		t.Fatal("expected error for unknown operation 'teleport'")
	}
}

func TestValidate_emptyAllowedTemplates_ok(t *testing.T) {
	// Empty slice = deny all templates (valid, intentional hard deny)
	rules := &Rules{
		Version:          "1",
		AllowedTemplates: []string{},
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("Validate: %v (empty allowed_templates is valid — means deny all)", err)
	}
}

func TestValidate_emptyTemplateID_error(t *testing.T) {
	// A template ID that is an empty string is invalid
	rules := &Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256", ""},
	}
	if err := rules.Validate(); err == nil {
		t.Fatal("expected error for empty template ID in allowed_templates")
	}
}

func TestValidate_securityRequirements_ok(t *testing.T) {
	fips := true
	block := true
	rules := &Rules{
		Version: "1",
		SecurityRequirements: &SecurityRequirementRule{
			FIPSApproved:    &fips,
			BlockDeprecated: &block,
		},
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestValidate_invalidVersion_error(t *testing.T) {
	// Only "1" is supported for the moment
	rules := &Rules{
		Version: "99",
	}
	if err := rules.Validate(); err == nil {
		t.Fatal("expected error for unsupported version '99'")
	}
}

func TestValidate_versionEmptyWithSections_error(t *testing.T) {
	// If rules have any sections, version must be specified
	rules := &Rules{
		AllowedTemplates: []string{"ecdsa-p256-sha256"},
	}
	if err := rules.Validate(); err == nil {
		t.Fatal("expected error: version required when sections are present")
	}
}

func TestValidate_allKeyOperations_ok(t *testing.T) {
	rules := &Rules{
		Version: "1",
		AllowedOperations: &OperationRule{
			KeyOperations: []string{
				"create_key", "read_key", "delete_key",
				"sign", "verify", "encrypt", "decrypt",
				"wrap", "unwrap", "derive_key", "rotate_key",
			},
		},
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("Validate all key operations: %v", err)
	}
}

func TestValidate_emptyKeyOperations_ok(t *testing.T) {
	// Empty key_operations = deny all operations (valid, intentional)
	rules := &Rules{
		Version: "1",
		AllowedOperations: &OperationRule{
			KeyOperations: []string{},
		},
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("Validate: %v (empty key_operations is valid — means deny all)", err)
	}
}

func TestValidate_versionOnlyNoSections_ok(t *testing.T) {
	rules := &Rules{
		Version: "1",
	}
	if err := rules.Validate(); err != nil {
		t.Errorf("Validate version-only: %v", err)
	}
}

// ============================================================================
// provider_requirements
// ============================================================================

func TestParseRules_providerRequirements(t *testing.T) {
	rules, err := ParseRules([]byte(`{
		"version": "1",
		"provider_requirements": {
			"fips_140_certified": true,
			"min_fips_level": 2,
			"common_criteria_certified": true,
			"formally_verified": true,
			"memory_safe": true,
			"constant_time": true,
			"side_channel_hardened": true,
			"no_known_cve": true,
			"approved_generation": true
		}
	}`))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	want := core.ProviderRequirements{
		FIPS140Certified:        true,
		MinFIPS140Level:         2,
		CommonCriteriaCertified: true,
		FormallyVerified:        true,
		MemorySafe:              true,
		ConstantTime:            true,
		SideChannelHardened:     true,
		NoKnownCVE:              true,
		ApprovedGeneration:      true,
	}
	if got := rules.ProviderRequirements.Requirements(); got != want {
		t.Errorf("Requirements = %+v, want %+v", got, want)
	}
}

func TestParseRules_providerRequirements_rejectsUnknownAndMistypedFields(t *testing.T) {
	for name, section := range map[string]string{
		"misspelt requirement": `{"fips140_certified": true}`,
		"preference":           `{"prefer_hardware_accelerated": true}`,
		"level as enum name":   `{"min_fips_level": "FIPS_140_LEVEL_3"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRules([]byte(`{"version": "1", "provider_requirements": ` + section + `}`))
			if err == nil {
				t.Fatal("ParseRules: expected an error, a requirement that cannot be read must not be ignored")
			}
		})
	}
}

func TestProviderRequirementRule_nilRequiresNothing(t *testing.T) {
	var rule *ProviderRequirementRule
	if got := rule.Requirements(); !got.IsZero() {
		t.Errorf("Requirements = %+v, want zero", got)
	}
}

func TestValidate_providerRequirements(t *testing.T) {
	for level := range uint32(core.MaxFIPS140Level + 1) {
		rules := &Rules{Version: "1", ProviderRequirements: &ProviderRequirementRule{MinFIPS140Level: level}}
		if err := rules.Validate(); err != nil {
			t.Errorf("Validate min_fips_level %d: %v", level, err)
		}
	}
	rules := &Rules{Version: "1", ProviderRequirements: &ProviderRequirementRule{MinFIPS140Level: core.MaxFIPS140Level + 1}}
	if err := rules.Validate(); err == nil {
		t.Error("Validate: expected an error for min_fips_level above 4")
	}
	if err := (&Rules{ProviderRequirements: &ProviderRequirementRule{}}).Validate(); err == nil {
		t.Error("Validate: expected an error, version is required when provider_requirements is present")
	}
}
