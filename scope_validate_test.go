package core_test

// // ============================================================================
// // ParseScopeSpec
// // ============================================================================

// func TestParseScopeSpec_roundTrip(t *testing.T) {
// 	original := core.ScopeSpec{
// 		Primitive: core.PrimitiveSignature,
// 		Scope:     core.SignatureScopeStandard,
// 	}
// 	ctx := context.Background()
// 	data, err := original.Serialize(ctx)
// 	if err != nil {
// 		t.Fatalf("Serialize: %v", err)
// 	}

// 	got, err := core.ParseScopeSpec(ctx, data)
// 	if err != nil {
// 		t.Fatalf("ParseScopeSpec: %v", err)
// 	}
// 	if got.Primitive != original.Primitive || got.Scope != original.Scope {
// 		t.Errorf("round-trip mismatch: got %+v, want %+v", got, original)
// 	}
// }

// func TestParseScopeSpec_emptyData(t *testing.T) {
// 	ctx := context.Background()
// 	_, err := core.ParseScopeSpec(ctx, nil)
// 	if err == nil {
// 		t.Fatal("expected error for nil data")
// 	}
// 	_, err = core.ParseScopeSpec(ctx, []byte{})
// 	if err == nil {
// 		t.Fatal("expected error for empty data")
// 	}
// }

// func TestParseScopeSpec_invalidJSON(t *testing.T) {
// 	ctx := context.Background()
// 	_, err := core.ParseScopeSpec(ctx, []byte("not-json"))
// 	if err == nil {
// 		t.Fatal("expected error for invalid JSON")
// 	}
// }

// // ============================================================================
// // ValidateSignatureScope
// // ============================================================================

// func TestValidateSignatureScope_match(t *testing.T) {
// 	ctx := context.Background()
// 	keyScope := core.ScopeSpec{
// 		Primitive: core.PrimitiveSignature,
// 		Scope:     core.SignatureScopeStandard,
// 	}
// 	err := core.ValidateSignatureScope(ctx, keyScope, core.SignatureScopeStandard)
// 	if err != nil {
// 		t.Fatalf("expected no error for matching scope, got: %v", err)
// 	}
// }

// func TestValidateSignatureScope_withContextMatch(t *testing.T) {
// 	ctx := context.Background()
// 	keyScope := core.ScopeSpec{
// 		Primitive: core.PrimitiveSignature,
// 		Scope:     core.SignatureScopeWithContext,
// 	}
// 	err := core.ValidateSignatureScope(ctx, keyScope, core.SignatureScopeWithContext)
// 	if err != nil {
// 		t.Fatalf("expected no error for matching with_context scope, got: %v", err)
// 	}
// }

// func TestValidateSignatureScope_mismatch(t *testing.T) {
// 	ctx := context.Background()
// 	keyScope := core.ScopeSpec{
// 		Primitive: core.PrimitiveSignature,
// 		Scope:     core.SignatureScopeStandard,
// 	}
// 	err := core.ValidateSignatureScope(ctx, keyScope, core.SignatureScopeWithContext)
// 	if err == nil {
// 		t.Fatal("expected error for scope mismatch")
// 	}
// }

// func TestValidateSignatureScope_emptyCallerScope(t *testing.T) {
// 	ctx := context.Background()
// 	keyScope := core.ScopeSpec{
// 		Primitive: core.PrimitiveSignature,
// 		Scope:     core.SignatureScopeStandard,
// 	}
// 	err := core.ValidateSignatureScope(ctx, keyScope, "")
// 	if err == nil {
// 		t.Fatal("expected error for empty caller scope")
// 	}
// }

// func TestValidateSignatureScope_prehashedScopes(t *testing.T) {
// 	ctx := context.Background()
// 	// Verify prehashed variants work correctly.
// 	tests := []struct {
// 		name        string
// 		keyScope    core.Scope
// 		callerScope core.Scope
// 		wantErr     bool
// 	}{
// 		{"prehashed match", core.SignatureScopePrehashed, core.SignatureScopePrehashed, false},
// 		{"prehashed_with_context match", core.SignatureScopePrehashedWithContext, core.SignatureScopePrehashedWithContext, false},
// 		{"prehashed vs standard mismatch", core.SignatureScopePrehashed, core.SignatureScopeStandard, true},
// 		{"standard vs prehashed mismatch", core.SignatureScopeStandard, core.SignatureScopePrehashed, true},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			ks := core.ScopeSpec{Primitive: core.PrimitiveSignature, Scope: tt.keyScope}
// 			err := core.ValidateSignatureScope(ctx, ks, tt.callerScope)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("ValidateSignatureScope(%q, %q): err=%v, wantErr=%v",
// 					tt.keyScope, tt.callerScope, err, tt.wantErr)
// 			}
// 		})
// 	}
// }
