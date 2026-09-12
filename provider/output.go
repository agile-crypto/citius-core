package provider

import (
	metapb "github.com/agile-crypto/citius-api-go/gen/go/messages"
)

// NoOutput builds a ProviderOutput with the no_output arm set and the given
// artifact encoding recorded ("der", "p1363", "raw", ...).
//
// metadata.proto requires every provider response to set algorithm_output
// explicitly — an unset oneof means the provider forgot to set it, and the
// core MUST reject the response.  Signature, asymmetric-encryption, key-wrap,
// and MAC operations have no system-generated parameters to report, so they
// use this helper to make that "nothing to report" state explicit rather than
// leaving the field nil.
//
// Use this only when the operation PRODUCES a new serialized artifact whose
// encoding a later consumer needs — Sign, SignDigest, Encrypt, GenerateKey,
// ExportPublicKey.  Operations that only check or consume an existing
// artifact (Verify, VerifyDigest, Decrypt) have nothing to encode; use
// NoOutputUnencoded for those instead of guessing a value here.
func NoOutput(encoding string) *metapb.ProviderOutput {
	return &metapb.ProviderOutput{
		AlgorithmOutput: &metapb.ProviderOutput_NoOutput{
			NoOutput: &metapb.NoAlgorithmOutput{},
		},
		Encoding: encoding,
	}
}

// NoOutputUnencoded builds a ProviderOutput with the no_output arm set and no
// encoding declared.
//
// encoding documents "how the cryptographic output (ciphertext, signature,
// wrapped key) is serialized" (metadata.proto).  Verify, VerifyDigest, and
// Decrypt don't produce one of those — Verify/VerifyDigest return a bool, and
// Decrypt's recovered plaintext is application data, not a serialized crypto
// artifact.  The proto places no required/min_len constraint on encoding, so
// leaving it empty is a valid, meaningful "not applicable" — not a value the
// provider forgot to set.
func NoOutputUnencoded() *metapb.ProviderOutput {
	return NoOutput("")
}

// AeadOutput builds a ProviderOutput with the aead_output arm set, carrying
// the system-generated nonce and the authentication tag length — the
// parameters an AEAD cipher (GCM, CCM, ChaCha20-Poly1305) must record at
// encryption time for decryption to succeed later. Use this from Encrypt;
// Decrypt has nothing new to report and should use NoOutputUnencoded.
func AeadOutput(nonce []byte, tagLengthBytes uint32, encoding string) *metapb.ProviderOutput {
	return &metapb.ProviderOutput{
		AlgorithmOutput: &metapb.ProviderOutput_AeadOutput{
			AeadOutput: &metapb.AeadOutput{
				Nonce:          nonce,
				TagLengthBytes: tagLengthBytes,
			},
		},
		Encoding: encoding,
	}
}

// BlockCipherOutput builds a ProviderOutput with the block_cipher_output arm
// set, carrying the system-generated IV — the parameter block cipher modes
// (CBC, OFB, CFB) must record at encryption time for decryption to succeed
// later. Use this from Encrypt; Decrypt has nothing new to report and should
// use NoOutputUnencoded.
func BlockCipherOutput(iv []byte, encoding string) *metapb.ProviderOutput {
	return &metapb.ProviderOutput{
		AlgorithmOutput: &metapb.ProviderOutput_BlockCipherOutput{
			BlockCipherOutput: &metapb.BlockCipherOutput{
				Iv: iv,
			},
		},
		Encoding: encoding,
	}
}
