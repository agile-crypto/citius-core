package core

// // ValidateSignatureScope checks that callerScope is compatible with the
// // key's declared scope specification.
// //
// // This is a domain rule: the key's ScopeSpec (set at creation time / after transformation)
// // is the authoritative source of truth for which scope variant the key was created
// // to serve. The caller must declare the same scope when performing operations.
// //
// // Returns a non-nil error if:
// //   - callerScope is empty (no scope_params were provided in the request)
// //   - callerScope does not match keyScope.Scope
// func ValidateSignatureScope(ctx context.Context, keyScope ScopeSpec, callerScope Scope) error {
// 	const op errors.Op = "core.ValidateSignatureScope"
// 	if callerScope == "" {
// 		return errors.New(ctx, op, errors.CodeInvalidArgument,
// 			"caller must declare a signature scope")
// 	}
// 	if keyScope.Scope != callerScope {
// 		return errors.New(ctx, op, errors.CodeInvalidArgument,
// 			fmt.Sprintf("scope_params %q does not match key scope %q",
// 				callerScope, keyScope.Scope))
// 	}
// 	return nil
// }
