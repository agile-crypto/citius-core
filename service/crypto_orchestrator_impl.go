package service

import (
	"context"
	"fmt"
	"slices"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/template"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"google.golang.org/protobuf/proto"
)

// cryptoOrchestrator implements CryptoOrchestrator.
// It coordinates key retrieval, policy validation, and provider dispatch
// for cryptographic operations.
type cryptoOrchestrator struct {
	keys      key.ReadOnlyRepository
	policy    policy.Engine
	providers provider.Registry
	templates template.Registry
}

// NewCryptoOrchestrator creates a new CryptoOrchestrator.
// All four dependencies are required; returns an error if any is nil.
func NewCryptoOrchestrator(
	kr key.ReadOnlyRepository,
	pe policy.Engine,
	pr provider.Registry,
	tr template.Registry,
) (CryptoOrchestrator, error) {
	const op errors.Op = "service.NewCryptoOrchestrator"
	ctx := context.Background()

	if kr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key reader must not be nil")
	}
	if pe == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"policy engine must not be nil")
	}
	if pr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"provider registry must not be nil")
	}
	if tr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"template registry must not be nil")
	}

	return &cryptoOrchestrator{
		keys:      kr,
		policy:    pe,
		providers: pr,
		templates: tr,
	}, nil
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

// applySignScopeParams copies the caller's scope_params oneof into provReq.
func applySignScopeParams(req crypto.SignRequest, provReq *providerpb.SignRequest) {
	switch {
	case req.NoContext != nil:
		provReq.ScopeParams = &providerpb.SignRequest_NoContext{NoContext: req.NoContext}
	case req.DomainContext != nil:
		provReq.ScopeParams = &providerpb.SignRequest_DomainContext{DomainContext: req.DomainContext}
	case req.VendorContext != nil:
		provReq.ScopeParams = &providerpb.SignRequest_VendorContext{VendorContext: req.VendorContext}
	}
}

// applyDigestSignScopeParams copies the caller's scope_params oneof into provReq.
func applyDigestSignScopeParams(req crypto.DigestSignRequest, provReq *providerpb.SignDigestRequest) {
	switch {
	case req.NoContext != nil:
		provReq.ScopeParams = &providerpb.SignDigestRequest_NoContext{NoContext: req.NoContext}
	case req.DomainContext != nil:
		provReq.ScopeParams = &providerpb.SignDigestRequest_DomainContext{DomainContext: req.DomainContext}
	case req.VendorContext != nil:
		provReq.ScopeParams = &providerpb.SignDigestRequest_VendorContext{VendorContext: req.VendorContext}
	}
}

// applyDigestVerifyScopeParams copies the caller's scope_params oneof into provReq.
func applyDigestVerifyScopeParams(req crypto.DigestVerifyRequest, provReq *providerpb.VerifyDigestRequest) {
	switch {
	case req.NoContext != nil:
		provReq.ScopeParams = &providerpb.VerifyDigestRequest_NoContext{NoContext: req.NoContext}
	case req.DomainContext != nil:
		provReq.ScopeParams = &providerpb.VerifyDigestRequest_DomainContext{DomainContext: req.DomainContext}
	case req.VendorContext != nil:
		provReq.ScopeParams = &providerpb.VerifyDigestRequest_VendorContext{VendorContext: req.VendorContext}
	}
}

func (o *cryptoOrchestrator) Sign(ctx context.Context, req crypto.SignRequest) (crypto.SignResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).Sign"

	// 1. Validate request.
	if req.KeyName == "" {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}
	if len(req.Payload) == 0 {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Payload must not be empty")
	}

	// 2. Load the key aggregate and apply the protecting-operation lifecycle rule.
	//    Sign creates new protected data, so only ACTIVE keys are permitted.
	k, err := o.keys.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}
	if encErr := k.CanPerformOriginatingCrypto(); encErr != nil {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, encErr.Error())
	}

	// 3a. Fetch the current version's material.
	kv, err := o.keys.GetCurrentVersion(ctx, k.GetPublicId())
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationSign, templateID, "")
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Resolve template → *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, req.SignatureScopeFields); err != nil {
		return crypto.SignResult{}, err
	}

	// 6b. Unmarshal stored GenerateKeyResponse to extract private key material.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Build provider-level SignRequest with scope_params oneof.
	// KeyMaterialEncoding carries the private key's stored encoding so the
	// provider selects the correct parser instead of guessing.
	provReq := &providerpb.SignRequest{
		KeyMaterial:         genResp.GetKeyMaterial(),
		Input:               req.Payload,
		Algorithm:           tmpl.GetAlgorithm(),
		KeyMaterialEncoding: genResp.GetKeyMaterialEncoding(),
	}
	applySignScopeParams(req, provReq)

	// 7. Perform sign.
	signer, ok := prov.(provider.Signer)
	if !ok {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("provider %q does not support signing", prov.Name()))
	}
	signResp, err := callSignerAndValidate(ctx, op, signer, provReq)
	if err != nil {
		return crypto.SignResult{}, err
	}

	// 8. Return result with metadata.
	return crypto.SignResult{
		Signature:    signResp.GetSignature(),
		KeyName:      req.KeyName,
		KeyVersion:   kv.GetVersion(),
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       signResp.GetOutput(),
	}, nil
}

// callSignerAndValidate calls the provider's Sign and enforces the
// ProviderOutput contract (an unset algorithm_output is a provider bug, not
// a caller error).  Extracted for uniformity with callVerifierAndValidate,
// callDigestSignerAndValidate, and callDigestVerifierAndValidate — all four
// sign/verify orchestrator methods follow the same call-provider-then-validate
// shape.
func callSignerAndValidate(ctx context.Context, op errors.Op, signer provider.Signer, provReq *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	signResp, err := signer.Sign(ctx, provReq)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, signResp.GetOutput()); err != nil {
		return nil, err
	}
	return signResp, nil
}

func (o *cryptoOrchestrator) Verify(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).Verify"

	// 1. Validate request.
	if req.KeyName == "" {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}

	// 2. Load the key aggregate and apply the processing-operation lifecycle rule.
	//    Verify processes existing signatures, so ACTIVE, SUSPENDED, and
	//    DEACTIVATED ("legacy") keys are permitted.
	k, err := o.keys.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}
	if decErr := k.CanPerformReceivingCrypto(); decErr != nil {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, decErr.Error())
	}

	// 2a. Fetch the right version's material (includes public key bytes).
	kv, err := o.keys.GetVersion(ctx, k.GetPublicId(), req.KeyVersion)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 3. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationVerify, templateID, "")
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Resolve template => *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 5a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, req.SignatureScopeFields); err != nil {
		return crypto.VerifyResult{}, err
	}

	// 5b. Unmarshal stored GenerateKeyResponse to extract public key bytes.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Build provider-level VerifyRequest with scope_params oneof.
	//    Verify receives the public key bytes, not the private key material.
	// KeyMaterialEncoding here is the PUBLIC key's encoding — VerifyRequest
	// carries the public half.
	provReq := &providerpb.VerifyRequest{
		KeyMaterial:         genResp.GetPublicKeyBytes(),
		Input:               req.Payload,
		Signature:           req.Signature,
		Algorithm:           tmpl.GetAlgorithm(),
		Output:              req.Output,
		KeyMaterialEncoding: genResp.GetPublicKeyEncoding(),
	}
	switch {
	case req.NoContext != nil:
		provReq.ScopeParams = &providerpb.VerifyRequest_NoContext{NoContext: req.NoContext}
	case req.DomainContext != nil:
		provReq.ScopeParams = &providerpb.VerifyRequest_DomainContext{DomainContext: req.DomainContext}
	case req.VendorContext != nil:
		provReq.ScopeParams = &providerpb.VerifyRequest_VendorContext{VendorContext: req.VendorContext}
	}

	// 7. Perform verify.
	verifier, ok := prov.(provider.Signer)
	if !ok {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("provider %q does not support verification", prov.Name()))
	}
	verifyResp, err := callVerifierAndValidate(ctx, op, verifier, provReq)
	if err != nil {
		return crypto.VerifyResult{}, err
	}

	// 8. Return result — invalid signature is NOT an error.
	return crypto.VerifyResult{
		Valid:        verifyResp.GetValid(),
		KeyName:      req.KeyName,
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       verifyResp.GetOutput(),
	}, nil
}

// callVerifierAndValidate calls the provider's Verify and enforces the
// ProviderOutput contract (an unset algorithm_output is a provider bug, not
// a caller error).  Extracted from Verify to keep cyclomatic complexity
// within linter limits.
func callVerifierAndValidate(ctx context.Context, op errors.Op, verifier provider.Signer, provReq *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	verifyResp, err := verifier.Verify(ctx, provReq)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, verifyResp.GetOutput()); err != nil {
		return nil, err
	}
	return verifyResp, nil
}

// DigestSign signs a pre-computed digest — the provider does NOT hash;
// req.HashAlgorithm describes the digest the caller supplies (for digest-size
// validation and, for RSA, the DigestInfo/PSS hash), never the signature
// scheme.  AlgorithmDetails is resolved from the key's bound template,
// exactly as Sign resolves it — no caller input selects the algorithm here
// either (see crypto.DigestSignRequest and the north-bound DigestSignRequest,
// neither of which carries an algorithm field).
func (o *cryptoOrchestrator) DigestSign(ctx context.Context, req crypto.DigestSignRequest) (crypto.SignResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).DigestSign"

	// 1. Validate request.
	if req.KeyName == "" {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}
	if len(req.Digest) == 0 {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Digest must not be empty")
	}

	// 2. Load the key aggregate and apply the protecting-operation lifecycle rule.
	//    DigestSign creates new protected data, so only ACTIVE keys are permitted.
	k, err := o.keys.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}
	if encErr := k.CanPerformOriginatingCrypto(); encErr != nil {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, encErr.Error())
	}

	// 3. Fetch the current version's material.
	kv, err := o.keys.GetCurrentVersion(ctx, k.GetPublicId())
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Validate operation against the key's attached policy.
	//    OperationDigestSign, not OperationSign — prehashed signing is a
	//    distinct grantable capability.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationDigestSign, templateID, "")
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Resolve template → *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, req.SignatureScopeFields); err != nil {
		return crypto.SignResult{}, err
	}

	// 6b. Unmarshal stored GenerateKeyResponse to extract private key material.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 7. Build provider-level SignDigestRequest with scope_params oneof.
	// KeyMaterialEncoding carries the private key's stored encoding — see Sign.
	provReq := &providerpb.SignDigestRequest{
		KeyMaterial:         genResp.GetKeyMaterial(),
		Digest:              req.Digest,
		HashAlgorithm:       req.HashAlgorithm,
		HashAlgorithmOid:    req.HashAlgorithmOID,
		Algorithm:           tmpl.GetAlgorithm(),
		KeyMaterialEncoding: genResp.GetKeyMaterialEncoding(),
	}
	applyDigestSignScopeParams(req, provReq)

	// 8. Perform digest sign.
	signer, ok := prov.(provider.Signer)
	if !ok {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("provider %q does not support signing", prov.Name()))
	}
	digestSignResp, err := callDigestSignerAndValidate(ctx, op, signer, provReq)
	if err != nil {
		return crypto.SignResult{}, err
	}

	// 9. Return result with metadata.
	return crypto.SignResult{
		Signature:    digestSignResp.GetSignature(),
		KeyName:      req.KeyName,
		KeyVersion:   kv.GetVersion(),
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       digestSignResp.GetOutput(),
	}, nil
}

// callDigestSignerAndValidate calls the provider's SignDigest and enforces
// the ProviderOutput contract (an unset algorithm_output is a provider bug,
// not a caller error).  Extracted for symmetry with callDigestVerifierAndValidate
// — DigestSign and DigestVerify are mirror-image operations, so both follow
// the same call-provider-then-validate shape even though DigestSign alone
// stays under the cyclomatic complexity limit inline.
func callDigestSignerAndValidate(ctx context.Context, op errors.Op, signer provider.Signer, provReq *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	digestSignResp, err := signer.SignDigest(ctx, provReq)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, digestSignResp.GetOutput()); err != nil {
		return nil, err
	}
	return digestSignResp, nil
}

// DigestVerify verifies a signature over a pre-computed digest.
func (o *cryptoOrchestrator) DigestVerify(ctx context.Context, req crypto.DigestVerifyRequest) (crypto.VerifyResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).DigestVerify"

	// 1. Validate request.
	if req.KeyName == "" {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}
	if len(req.Digest) == 0 {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Digest must not be empty")
	}

	// 2. Load the key aggregate and apply the processing-operation lifecycle rule.
	//    DigestVerify processes existing signatures, so ACTIVE, SUSPENDED, and
	//    DEACTIVATED ("legacy") keys are permitted.
	k, err := o.keys.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}
	if decErr := k.CanPerformReceivingCrypto(); decErr != nil {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, decErr.Error())
	}

	// 2a. Fetch the right version's material (includes public key bytes).
	kv, err := o.keys.GetVersion(ctx, k.GetPublicId(), req.KeyVersion)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 3. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationDigestVerify, templateID, "")
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Resolve template => *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 5a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, req.SignatureScopeFields); err != nil {
		return crypto.VerifyResult{}, err
	}

	// 5b. Unmarshal stored GenerateKeyResponse to extract public key bytes.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Build provider-level VerifyDigestRequest with scope_params oneof.
	//    DigestVerify receives the public key bytes, not the private key material.
	// KeyMaterialEncoding here is the PUBLIC key's encoding — see Verify.
	provReq := &providerpb.VerifyDigestRequest{
		KeyMaterial:         genResp.GetPublicKeyBytes(),
		Digest:              req.Digest,
		Signature:           req.Signature,
		HashAlgorithm:       req.HashAlgorithm,
		HashAlgorithmOid:    req.HashAlgorithmOID,
		Algorithm:           tmpl.GetAlgorithm(),
		Output:              req.Output,
		KeyMaterialEncoding: genResp.GetPublicKeyEncoding(),
	}
	applyDigestVerifyScopeParams(req, provReq)

	// 7. Perform digest verify.
	verifier, ok := prov.(provider.Signer)
	if !ok {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("provider %q does not support verification", prov.Name()))
	}
	digestVerifyResp, err := callDigestVerifierAndValidate(ctx, op, verifier, provReq)
	if err != nil {
		return crypto.VerifyResult{}, err
	}

	// 8. Return result — invalid signature is NOT an error.
	return crypto.VerifyResult{
		Valid:        digestVerifyResp.GetValid(),
		KeyName:      req.KeyName,
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       digestVerifyResp.GetOutput(),
	}, nil
}

// callDigestVerifierAndValidate calls the provider's VerifyDigest and
// enforces the ProviderOutput contract.  Extracted from DigestVerify to keep
// cyclomatic complexity within linter limits (mirrors callVerifierAndValidate).
func callDigestVerifierAndValidate(ctx context.Context, op errors.Op, verifier provider.Signer, provReq *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	digestVerifyResp, err := verifier.VerifyDigest(ctx, provReq)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, digestVerifyResp.GetOutput()); err != nil {
		return nil, err
	}
	return digestVerifyResp, nil
}

// applyEncryptScopeParams copies the caller's scope_params oneof into provReq.
func applyEncryptScopeParams(sf crypto.EncryptionScopeFields, provReq *providerpb.EncryptRequest) {
	switch {
	case sf.NoParams != nil:
		provReq.ScopeParams = &providerpb.EncryptRequest_NoParams{NoParams: sf.NoParams}
	case sf.AeadParams != nil:
		provReq.ScopeParams = &providerpb.EncryptRequest_AeadParams{AeadParams: sf.AeadParams}
	case sf.XtsParams != nil:
		provReq.ScopeParams = &providerpb.EncryptRequest_XtsParams{XtsParams: sf.XtsParams}
	case sf.AsymmetricParams != nil:
		provReq.ScopeParams = &providerpb.EncryptRequest_AsymmetricParams{AsymmetricParams: sf.AsymmetricParams}
	case sf.VendorParams != nil:
		provReq.ScopeParams = &providerpb.EncryptRequest_VendorParams{VendorParams: sf.VendorParams}
	}
}

// applyDecryptScopeParams copies the caller's scope_params oneof into provReq.
func applyDecryptScopeParams(sf crypto.EncryptionScopeFields, provReq *providerpb.DecryptRequest) {
	switch {
	case sf.NoParams != nil:
		provReq.ScopeParams = &providerpb.DecryptRequest_NoParams{NoParams: sf.NoParams}
	case sf.AeadParams != nil:
		provReq.ScopeParams = &providerpb.DecryptRequest_AeadParams{AeadParams: sf.AeadParams}
	case sf.XtsParams != nil:
		provReq.ScopeParams = &providerpb.DecryptRequest_XtsParams{XtsParams: sf.XtsParams}
	case sf.AsymmetricParams != nil:
		provReq.ScopeParams = &providerpb.DecryptRequest_AsymmetricParams{AsymmetricParams: sf.AsymmetricParams}
	case sf.VendorParams != nil:
		provReq.ScopeParams = &providerpb.DecryptRequest_VendorParams{VendorParams: sf.VendorParams}
	}
}

func (o *cryptoOrchestrator) Encrypt(ctx context.Context, req crypto.EncryptRequest) (crypto.EncryptResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).Encrypt"

	// 1. Validate request.
	if req.KeyName == "" {
		return crypto.EncryptResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}
	if len(req.Plaintext) == 0 {
		return crypto.EncryptResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Plaintext must not be empty")
	}

	// 2. Load the key aggregate and apply the protecting-operation lifecycle
	//    rule. Encrypt creates new protected data, so only ACTIVE keys are
	//    permitted — the same rule Sign applies.
	k, err := o.keys.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.EncryptResult{}, errors.Wrap(ctx, op, err)
	}
	if encErr := k.CanPerformOriginatingCrypto(); encErr != nil {
		return crypto.EncryptResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, encErr.Error())
	}

	// 3. Fetch the current version's material.
	kv, err := o.keys.GetCurrentVersion(ctx, k.GetPublicId())
	if err != nil {
		return crypto.EncryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationEncrypt, templateID, "")
	if err != nil {
		return crypto.EncryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.EncryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Resolve template → *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.EncryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 6a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateEncryptionScopeParams(ctx, op, k, req.EncryptionScopeFields); err != nil {
		return crypto.EncryptResult{}, err
	}

	// 6b. Unmarshal stored GenerateKeyResponse to extract key material.
	// Symmetric ciphers have no public/private split — the same key_material
	// used at generation is used here, unlike Sign/Verify's two halves.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.EncryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 6c. Build provider-level EncryptRequest with scope_params oneof.
	// KeyMaterialEncoding carries the key's stored encoding — see Sign.
	provReq := &providerpb.EncryptRequest{
		KeyMaterial:         genResp.GetKeyMaterial(),
		Plaintext:           req.Plaintext,
		Algorithm:           tmpl.GetAlgorithm(),
		KeyMaterialEncoding: genResp.GetKeyMaterialEncoding(),
	}
	applyEncryptScopeParams(req.EncryptionScopeFields, provReq)

	// 7. Perform encrypt.
	cipher, ok := prov.(provider.Cipher)
	if !ok {
		return crypto.EncryptResult{}, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("provider %q does not support encryption", prov.Name()))
	}
	encResp, err := cipher.Encrypt(ctx, provReq)
	if err != nil {
		return crypto.EncryptResult{}, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, encResp.GetOutput()); err != nil {
		return crypto.EncryptResult{}, err
	}

	// 8. Return result with metadata.
	return crypto.EncryptResult{
		Ciphertext:   encResp.GetCiphertext(),
		KeyVersion:   kv.GetVersion(),
		Output:       encResp.GetOutput(),
		Algorithm:    templateID,
		ProviderName: prov.Name(),
	}, nil
}

func (o *cryptoOrchestrator) Decrypt(ctx context.Context, req crypto.DecryptRequest) (crypto.DecryptResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).Decrypt"

	// 1. Validate request.
	if req.KeyName == "" {
		return crypto.DecryptResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}
	if len(req.Ciphertext) == 0 {
		return crypto.DecryptResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Ciphertext must not be empty")
	}
	if req.Output == nil {
		return crypto.DecryptResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Output must not be nil")
	}

	// 2. Load the key aggregate and apply the processing-operation lifecycle
	//    rule. Decrypt processes existing protected data, so ACTIVE,
	//    SUSPENDED, and DEACTIVATED ("legacy") keys are permitted — the same
	//    rule Verify applies.
	k, err := o.keys.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.DecryptResult{}, errors.Wrap(ctx, op, err)
	}
	if decErr := k.CanPerformReceivingCrypto(); decErr != nil {
		return crypto.DecryptResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, decErr.Error())
	}

	// 2a. Fetch the right version's material.
	kv, err := o.keys.GetVersion(ctx, k.GetPublicId(), req.KeyVersion)
	if err != nil {
		return crypto.DecryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 3. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationDecrypt, templateID, "")
	if err != nil {
		return crypto.DecryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.DecryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Resolve template → *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.DecryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 5a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateEncryptionScopeParams(ctx, op, k, req.EncryptionScopeFields); err != nil {
		return crypto.DecryptResult{}, err
	}

	// 5b. Unmarshal stored GenerateKeyResponse to extract key material.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.DecryptResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Build provider-level DecryptRequest with scope_params oneof.
	//    req.Output — the ProviderOutput the core extracted from the stored
	//    OperationMetadata that Encrypt originally produced — carries the
	//    nonce/IV; the provider never regenerates it for Decrypt.
	//    KeyMaterialEncoding carries the key's stored encoding — see Sign.
	provReq := &providerpb.DecryptRequest{
		KeyMaterial:         genResp.GetKeyMaterial(),
		Ciphertext:          req.Ciphertext,
		Output:              req.Output,
		Algorithm:           tmpl.GetAlgorithm(),
		KeyMaterialEncoding: genResp.GetKeyMaterialEncoding(),
	}
	applyDecryptScopeParams(req.EncryptionScopeFields, provReq)

	// 7. Perform decrypt.
	cipher, ok := prov.(provider.Cipher)
	if !ok {
		return crypto.DecryptResult{}, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("provider %q does not support decryption", prov.Name()))
	}
	decResp, err := cipher.Decrypt(ctx, provReq)
	if err != nil {
		return crypto.DecryptResult{}, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, decResp.GetOutput()); err != nil {
		return crypto.DecryptResult{}, err
	}

	// 8. Return result with metadata.
	return crypto.DecryptResult{
		Plaintext:    decResp.GetPlaintext(),
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       decResp.GetOutput(),
	}, nil
}

func (o *cryptoOrchestrator) WrapKey(ctx context.Context, _ crypto.WrapKeyRequest) (crypto.WrapKeyResult, error) {
	return crypto.WrapKeyResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).WrapKey", errors.CodeNotImplemented,
		"WrapKey is not yet implemented")
}

func (o *cryptoOrchestrator) UnwrapKey(ctx context.Context, _ crypto.UnwrapKeyRequest) (crypto.UnwrapKeyResult, error) {
	return crypto.UnwrapKeyResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).UnwrapKey", errors.CodeNotImplemented,
		"UnwrapKey is not yet implemented")
}

func (o *cryptoOrchestrator) DeriveKey(ctx context.Context, _ crypto.DeriveKeyRequest) (*key.Key, error) {
	return nil, errors.New(ctx,
		"service.(cryptoOrchestrator).DeriveKey", errors.CodeNotImplemented,
		"DeriveKey is not yet implemented")
}

func (o *cryptoOrchestrator) GenerateMAC(ctx context.Context, _ crypto.MacRequest) (crypto.MacResult, error) {
	return crypto.MacResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).GenerateMAC", errors.CodeNotImplemented,
		"GenerateMAC is not yet implemented")
}

func (o *cryptoOrchestrator) VerifyMAC(ctx context.Context, _ crypto.VerifyMacRequest) (crypto.VerifyMacResult, error) {
	return crypto.VerifyMacResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).VerifyMAC", errors.CodeNotImplemented,
		"VerifyMAC is not yet implemented")
}

func (o *cryptoOrchestrator) Digest(ctx context.Context, _ crypto.DigestRequest) (crypto.DigestResult, error) {
	return crypto.DigestResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).Digest", errors.CodeNotImplemented,
		"Digest is not yet implemented")
}

func (o *cryptoOrchestrator) GenerateRandom(ctx context.Context, _ int) ([]byte, error) {
	return nil, errors.New(ctx,
		"service.(cryptoOrchestrator).GenerateRandom", errors.CodeNotImplemented,
		"GenerateRandom is not yet implemented")
}

// ---------------------------------------------------------------------------
// Scope-param validation helpers
// ---------------------------------------------------------------------------

// validateSignatureScopeParams validates that the caller's scope_params
// are compatible with the key's declared ScopeSpecification.
//
// The orchestrator handles:
//  1. Vendor short-circuit (vendor context bypasses standard scope matching)
//  2. Proto oneof arm → core.Scope mapping
//  3. Delegating semantic validation to core.ValidateSignatureScope
//  4. Wrapping core errors with ctx/op/code
//
// The proto oneof at the API boundary guarantees at-most-one variant.
// If none is set, callerScope maps to "" and core rejects it.
func validateSignatureScopeParams(
	ctx context.Context,
	op errors.Op,
	k *key.Key,
	sf crypto.SignatureScopeFields,
) error {
	// 1. Vendor context bypasses standard scope matching.
	if sf.VendorContext != nil {
		return nil
	}

	// 2. Map proto oneof arm => core.Scope.
	//    If no arm is set (all nil), callerScope is "",
	//    which core.ValidateSignatureScope rejects.
	var callerScope core.Scope
	switch {
	case sf.NoContext != nil:
		callerScope = core.ScopeSignatureStandard
	case sf.DomainContext != nil:
		callerScope = core.ScopeSignatureWithContext
	default:
		return errors.New(ctx, op, errors.CodeInvalidArgument, "signature scope field is required")
	}

	// 3. Deserialize the key's scope specification.
	keyScopeSpec := &core.ScopeSpecification{}
	err := keyScopeSpec.Deserialize(ctx, k.GetScopeSpecification())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if keyScopeSpec.Scope != callerScope {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"caller scope %q does not match key scope %q", callerScope, keyScopeSpec.Scope)
	}
	return nil
}

// validateEncryptionScopeParams validates that the caller's scope_params are
// compatible with the key's declared ScopeSpecification — the encryption
// analogue of validateSignatureScopeParams.
//
// AeadParams maps to the single core.ScopeAeadStandard scope (a random-nonce
// AEAD, as opposed to core.ScopeAeadDeterministic algorithms like AES-SIV,
// which this provider does not implement, so that distinction isn't made
// here). NoParams maps to a SET of two scopes — core.ScopeSymmetricCipherBlock
// (AES-CBC) and core.ScopeSymmetricCipherStream (AES-CTR) — because NoParams
// itself carries no information distinguishing block from stream cipher
// mode; the key's own ScopeSpecification, fixed at CreateKey time from the
// template, is what actually pins that down. XtsParams/AsymmetricParams have
// no provider implementation yet, so mapping them to a scope now would be
// guessing; they are rejected here rather than silently accepted with a
// wrong scope.
func validateEncryptionScopeParams(
	ctx context.Context,
	op errors.Op,
	k *key.Key,
	sf crypto.EncryptionScopeFields,
) error {
	// 1. Vendor params bypass standard scope matching.
	if sf.VendorParams != nil {
		return nil
	}

	// 2. Map proto oneof arm => the set of core.Scope values it's valid for.
	var allowedScopes []core.Scope
	switch {
	case sf.AeadParams != nil:
		allowedScopes = []core.Scope{core.ScopeAeadStandard}
	case sf.NoParams != nil:
		allowedScopes = []core.Scope{core.ScopeSymmetricCipherBlock, core.ScopeSymmetricCipherStream}
	default:
		return errors.New(ctx, op, errors.CodeInvalidArgument, "encryption scope field is required")
	}

	// 3. Deserialize the key's scope specification.
	keyScopeSpec := &core.ScopeSpecification{}
	err := keyScopeSpec.Deserialize(ctx, k.GetScopeSpecification())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if !slices.Contains(allowedScopes, keyScopeSpec.Scope) {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"caller scope_params do not match key scope %q", keyScopeSpec.Scope)
	}
	return nil
}

// Compile-time assertion
var _ CryptoOrchestrator = (*cryptoOrchestrator)(nil)
