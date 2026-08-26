/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/bbmumford/whisper"
)

// AuditVerdict represents the outcome of a community audit.
type AuditVerdict int

const (
	// AuditSafe indicates the auditor found no issues.
	AuditSafe AuditVerdict = iota
	// AuditSuspicious indicates potential concerns were found.
	AuditSuspicious
	// AuditMalicious indicates the app is definitively harmful.
	AuditMalicious
)

var (
	// ErrInvalidSignature is returned when a signature does not verify.
	ErrInvalidSignature = errors.New("audit: invalid signature")
	// ErrMissingKey is returned when the auditor public key is empty.
	ErrMissingKey = errors.New("audit: missing auditor public key")
	// ErrDuplicateAttestation is returned when the same auditor attests the same app twice.
	ErrDuplicateAttestation = errors.New("audit: duplicate attestation from same auditor")
)

// AuditAttestation is a signed statement from an auditor about an application.
type AuditAttestation struct {
	// AuditorPubKey is the ed25519 public key of the auditor.
	AuditorPubKey []byte
	// AppCID is the content identifier of the audited application.
	AppCID string
	// Verdict is the auditor's assessment.
	Verdict AuditVerdict
	// Comment is an optional human-readable explanation.
	Comment string
	// Timestamp is when the attestation was created.
	Timestamp time.Time
	// Signature is the ed25519 signature over the attestation payload.
	Signature []byte
}

// AuditWeight holds the factors used to compute an auditor's weighted influence.
type AuditWeight struct {
	// TrustScore is the base trust score (0.0 to 1.0).
	TrustScore float64
	// IdentityAge is how long the auditor identity has existed.
	IdentityAge time.Duration
	// AppsPublished is the number of apps the auditor has published.
	AppsPublished int
	// PriorAudits is the number of prior audits completed.
	PriorAudits int
	// AccuracyRate is the fraction of past audits that were accurate (0.0 to 1.0).
	AccuracyRate float64
}

// attestationPayload builds the canonical bytes that get signed.
func attestationPayload(a *AuditAttestation) []byte {
	h := sha256.New()
	h.Write(a.AuditorPubKey)
	h.Write([]byte(a.AppCID))
	h.Write([]byte{byte(a.Verdict)})
	h.Write([]byte(a.Comment))

	// Encode timestamp as unix nanos for determinism.
	ts := a.Timestamp.UnixNano()
	for i := 0; i < 8; i++ {
		h.Write([]byte{byte(ts >> (56 - i*8))})
	}
	return h.Sum(nil)
}

// SignAttestation signs the attestation using the given ed25519 private key.
// The AuditorPubKey field must already be set. The Signature field is populated.
func SignAttestation(a *AuditAttestation, key ed25519.PrivateKey) {
	payload := attestationPayload(a)
	a.Signature = ed25519.Sign(key, payload)
}

// VerifyAttestation checks that the attestation's signature is valid
// against the embedded AuditorPubKey.
func VerifyAttestation(a *AuditAttestation) bool {
	if len(a.AuditorPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return false
	}
	payload := attestationPayload(a)
	return ed25519.Verify(a.AuditorPubKey, payload, a.Signature)
}

// ComputeWeight calculates a weighted influence score for an auditor.
//
// Formula:
//
//	weight = trustScore * ageMul * activityMul * accuracyMul
//
// Where:
//   - ageMul     = min(1.0, ln(1 + ageDays) / ln(366))      — saturates at ~1 year
//   - activityMul = min(1.0, ln(1 + apps + audits) / ln(101)) — saturates at ~100
//   - accuracyMul = accuracyRate^2                            — penalises inaccuracy
func ComputeWeight(w AuditWeight) float64 {
	if w.TrustScore <= 0 {
		return 0
	}

	// Age multiplier: logarithmic ramp, saturates at ~365 days.
	ageDays := w.IdentityAge.Hours() / 24
	ageMul := math.Min(1.0, math.Log1p(ageDays)/math.Log(366))

	// Activity multiplier: logarithmic ramp over published apps + prior audits.
	activity := float64(w.AppsPublished + w.PriorAudits)
	activityMul := math.Min(1.0, math.Log1p(activity)/math.Log(101))

	// Accuracy multiplier: quadratic penalty for low accuracy.
	acc := math.Max(0, math.Min(1.0, w.AccuracyRate))
	accuracyMul := acc * acc

	weight := w.TrustScore * ageMul * activityMul * accuracyMul
	return math.Max(0, math.Min(1.0, weight))
}

// auditTopic is the Whisper topic used for broadcasting audit attestations.
const auditTopic = "minerva.audits"

// AuditRegistry stores attestations indexed by AppCID.
type AuditRegistry struct {
	mu            sync.RWMutex
	attestations  map[string][]*AuditAttestation // appCID -> attestations
	seen          map[string]map[string]bool     // appCID -> set of auditor hex keys
	whisperEngine *whisper.Engine
}

// NewAuditRegistry creates a new empty audit registry wired to the given Whisper engine.
// The engine may be nil if Whisper is not available (local-only mode).
func NewAuditRegistry(engine *whisper.Engine) *AuditRegistry {
	r := &AuditRegistry{
		attestations:  make(map[string][]*AuditAttestation),
		seen:          make(map[string]map[string]bool),
		whisperEngine: engine,
	}

	// Subscribe to incoming attestations if Whisper is available.
	if engine != nil {
		// Register the topic as BroadcastOnly (ignore error if already registered).
		_ = engine.RegisterTopic(auditTopic, whisper.TopicConfig{
			Mode: whisper.BroadcastOnly,
		})
		engine.Subscribe(auditTopic, &auditSubscriber{registry: r})
	}

	return r
}

// Submit adds a verified attestation to the registry.
// Returns ErrInvalidSignature if the signature does not verify.
// Returns ErrDuplicateAttestation if the same auditor already attested this app.
func (r *AuditRegistry) Submit(a *AuditAttestation) error {
	if len(a.AuditorPubKey) == 0 {
		return ErrMissingKey
	}
	if !VerifyAttestation(a) {
		return ErrInvalidSignature
	}

	auditorHex := string(a.AuditorPubKey) // use raw bytes as map key

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.seen[a.AppCID] == nil {
		r.seen[a.AppCID] = make(map[string]bool)
	}
	if r.seen[a.AppCID][auditorHex] {
		return ErrDuplicateAttestation
	}

	r.seen[a.AppCID][auditorHex] = true
	r.attestations[a.AppCID] = append(r.attestations[a.AppCID], a)

	// Broadcast via Whisper if available.
	if r.whisperEngine != nil {
		if data, err := json.Marshal(a); err == nil {
			_ = r.whisperEngine.Publish(auditTopic, data)
		}
	}

	return nil
}

// auditSubscriber implements whisper.Subscriber for incoming audit attestations.
type auditSubscriber struct {
	registry *AuditRegistry
}

func (s *auditSubscriber) OnBroadcast(_ string, _ string, payload []byte) {
	var a AuditAttestation
	if err := json.Unmarshal(payload, &a); err != nil {
		return
	}
	// Submit validates signature and deduplicates; ignore errors.
	_ = s.registry.Submit(&a)
}

// Lookup returns all attestations for the given app CID.
func (r *AuditRegistry) Lookup(appCID string) []*AuditAttestation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	src := r.attestations[appCID]
	if len(src) == 0 {
		return nil
	}
	result := make([]*AuditAttestation, len(src))
	copy(result, src)
	return result
}

// Summary returns counts of each verdict type for the given app CID.
func (r *AuditRegistry) Summary(appCID string) (safe, suspicious, malicious int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, a := range r.attestations[appCID] {
		switch a.Verdict {
		case AuditSafe:
			safe++
		case AuditSuspicious:
			suspicious++
		case AuditMalicious:
			malicious++
		}
	}
	return
}
