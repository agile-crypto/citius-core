// Package key contains the Key and Version domain types.
//
// Each type embeds its generated storage proto (*storepb.StoredKey,
// *storepb.StoredKeyVersion) and adds domain behaviour: validation
// (VetForWrite), deep copying (Clone), and typed accessors.
//
// Key is the primary domain aggregate. Version represents one version
// of a key's cryptographic material, using the four-field encryption
// pattern (plaintext, ciphertext, HMAC, wrapping key ID).
package key
