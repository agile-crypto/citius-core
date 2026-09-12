// Package policy contains the Policy domain type and the governance
// interfaces for the policy bounded context.
//
// Policies define governance rules that control what the system allows:
// which algorithms, operations, and providers are permitted. Authorization
// (RBAC/ACL) is the transport layer's responsibility and is not mixed here.
//
// Domain type:
//   - Policy embeds *storepb.StoredPolicy and adds VetForWrite validation.
//
// Interfaces:
//   - Engine (domain service): ValidateOperation, ValidateKeyCreation,
//     AllowedTemplates, plus policy CRUD (Create/Get/Update/Delete/List).
//   - Repository: persistence contract for policy records;
//     implementations live in internal/storage/.
package policy
