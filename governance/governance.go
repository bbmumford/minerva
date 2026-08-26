/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package governance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/bbmumford/whisper"
)

// ProposalStatus represents the lifecycle state of a proposal.
type ProposalStatus int

const (
	// StatusDraft indicates the proposal has not yet been submitted for voting.
	StatusDraft ProposalStatus = iota
	// StatusActive indicates voting is open.
	StatusActive
	// StatusPassed indicates the proposal received enough support.
	StatusPassed
	// StatusRejected indicates the proposal was rejected.
	StatusRejected
	// StatusWithdrawn indicates the author withdrew the proposal.
	StatusWithdrawn
)

// VoteChoice represents a single vote.
type VoteChoice int

const (
	// VoteFor indicates support for the proposal.
	VoteFor VoteChoice = iota
	// VoteAgainst indicates opposition to the proposal.
	VoteAgainst
	// VoteAbstain indicates a deliberate abstention.
	VoteAbstain
)

var (
	// ErrProposalNotFound is returned when looking up a nonexistent proposal.
	ErrProposalNotFound = errors.New("governance: proposal not found")
	// ErrProposalExists is returned when a proposal with the same ID already exists.
	ErrProposalExists = errors.New("governance: proposal already exists")
	// ErrInvalidSignature is returned when a signature does not verify.
	ErrInvalidSignature = errors.New("governance: invalid signature")
	// ErrVotingClosed is returned when voting on a non-active proposal.
	ErrVotingClosed = errors.New("governance: voting is closed")
	// ErrVotingExpired is returned when voting after the deadline.
	ErrVotingExpired = errors.New("governance: voting period has expired")
	// ErrDuplicateVote is returned when a voter votes on the same proposal twice.
	ErrDuplicateVote = errors.New("governance: duplicate vote from same voter")
	// ErrMissingID is returned when a proposal or vote has an empty ID.
	ErrMissingID = errors.New("governance: missing proposal ID")
)

// ProtocolProposal is a signed governance proposal for protocol changes.
type ProtocolProposal struct {
	// ID is a unique identifier for the proposal.
	ID string
	// Title is a short summary of the proposal.
	Title string
	// Description is the full text of the proposal.
	Description string
	// SpecCID is the content identifier of the detailed specification.
	SpecCID string
	// AuthorPubKey is the ed25519 public key of the proposal author.
	AuthorPubKey []byte
	// Signature is the ed25519 signature over the proposal payload.
	Signature []byte
	// CreatedAt is when the proposal was created.
	CreatedAt time.Time
	// VotingEnds is the deadline for voting.
	VotingEnds time.Time
	// Status is the current lifecycle state.
	Status ProposalStatus
}

// ProposalVote is a signed vote on a governance proposal.
type ProposalVote struct {
	// ProposalID is the ID of the proposal being voted on.
	ProposalID string
	// VoterPubKey is the ed25519 public key of the voter.
	VoterPubKey []byte
	// Vote is the voter's choice.
	Vote VoteChoice
	// Signature is the ed25519 signature over the vote payload.
	Signature []byte
}

// proposalPayload builds the canonical bytes for proposal signing.
func proposalPayload(p *ProtocolProposal) []byte {
	h := sha256.New()
	h.Write([]byte(p.ID))
	h.Write([]byte(p.Title))
	h.Write([]byte(p.Description))
	h.Write([]byte(p.SpecCID))
	h.Write(p.AuthorPubKey)

	// Encode timestamps as unix nanos.
	created := p.CreatedAt.UnixNano()
	ends := p.VotingEnds.UnixNano()
	for i := 0; i < 8; i++ {
		h.Write([]byte{byte(created >> (56 - i*8))})
	}
	for i := 0; i < 8; i++ {
		h.Write([]byte{byte(ends >> (56 - i*8))})
	}
	return h.Sum(nil)
}

// votePayload builds the canonical bytes for vote signing.
func votePayload(v *ProposalVote) []byte {
	h := sha256.New()
	h.Write([]byte(v.ProposalID))
	h.Write(v.VoterPubKey)
	h.Write([]byte{byte(v.Vote)})
	return h.Sum(nil)
}

// SignProposal signs the proposal with the given ed25519 private key.
func SignProposal(p *ProtocolProposal, key ed25519.PrivateKey) {
	payload := proposalPayload(p)
	p.Signature = ed25519.Sign(key, payload)
}

// VerifyProposal checks that the proposal's signature is valid.
func VerifyProposal(p *ProtocolProposal) bool {
	if len(p.AuthorPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return false
	}
	payload := proposalPayload(p)
	return ed25519.Verify(p.AuthorPubKey, payload, p.Signature)
}

// SignVote signs the vote with the given ed25519 private key.
func SignVote(v *ProposalVote, key ed25519.PrivateKey) {
	payload := votePayload(v)
	v.Signature = ed25519.Sign(key, payload)
}

// VerifyVote checks that the vote's signature is valid.
func VerifyVote(v *ProposalVote) bool {
	if len(v.VoterPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(v.Signature) != ed25519.SignatureSize {
		return false
	}
	payload := votePayload(v)
	return ed25519.Verify(v.VoterPubKey, payload, v.Signature)
}

// governanceTopic is the Whisper topic used for governance proposals and votes.
const governanceTopic = "minerva.governance"

// governanceEnvelope wraps either a proposal or vote for wire serialization.
type governanceEnvelope struct {
	Proposal *ProtocolProposal `json:"proposal,omitempty"`
	Vote     *ProposalVote     `json:"vote,omitempty"`
}

// GovernanceRegistry manages protocol proposals and their votes.
type GovernanceRegistry struct {
	mu            sync.RWMutex
	proposals     map[string]*ProtocolProposal
	votes         map[string][]*ProposalVote     // proposalID -> votes
	voters        map[string]map[string]bool      // proposalID -> set of voter keys
	whisperEngine *whisper.Engine
}

// NewGovernanceRegistry creates a new empty governance registry wired to the
// given Whisper engine. The engine may be nil for local-only mode.
func NewGovernanceRegistry(engine *whisper.Engine) *GovernanceRegistry {
	g := &GovernanceRegistry{
		proposals:     make(map[string]*ProtocolProposal),
		votes:         make(map[string][]*ProposalVote),
		voters:        make(map[string]map[string]bool),
		whisperEngine: engine,
	}

	// Subscribe to incoming governance messages if Whisper is available.
	if engine != nil {
		// Governance uses StatefulMerge for consensus convergence, but since
		// we don't have a StateStore implementation yet, register as BroadcastOnly
		// to enable propagation. Migration to StatefulMerge is a follow-up.
		_ = engine.RegisterTopic(governanceTopic, whisper.TopicConfig{
			Mode: whisper.BroadcastOnly,
		})
		engine.Subscribe(governanceTopic, &governanceSubscriber{registry: g})
	}

	return g
}

// governanceSubscriber implements whisper.Subscriber for incoming governance messages.
type governanceSubscriber struct {
	registry *GovernanceRegistry
}

func (s *governanceSubscriber) OnBroadcast(_ string, _ string, payload []byte) {
	var env governanceEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return
	}
	if env.Proposal != nil {
		_ = s.registry.SubmitProposal(env.Proposal)
	}
	if env.Vote != nil {
		_ = s.registry.CastVote(env.Vote)
	}
}

// SubmitProposal adds a signed proposal to the registry and marks it active.
// The proposal must have a valid signature and unique ID.
func (g *GovernanceRegistry) SubmitProposal(p *ProtocolProposal) error {
	if p.ID == "" {
		return ErrMissingID
	}
	if !VerifyProposal(p) {
		return ErrInvalidSignature
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.proposals[p.ID]; exists {
		return ErrProposalExists
	}

	// Mark active on submission.
	p.Status = StatusActive
	g.proposals[p.ID] = p

	// Broadcast via Whisper if available.
	if g.whisperEngine != nil {
		env := governanceEnvelope{Proposal: p}
		if data, err := json.Marshal(env); err == nil {
			_ = g.whisperEngine.Publish(governanceTopic, data)
		}
	}

	return nil
}

// CastVote adds a signed vote to the given proposal.
// The proposal must exist, be active, and voting must not have expired.
// Each voter may only vote once per proposal.
func (g *GovernanceRegistry) CastVote(v *ProposalVote) error {
	if v.ProposalID == "" {
		return ErrMissingID
	}
	if !VerifyVote(v) {
		return ErrInvalidSignature
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	p, exists := g.proposals[v.ProposalID]
	if !exists {
		return ErrProposalNotFound
	}
	if p.Status != StatusActive {
		return ErrVotingClosed
	}
	if !p.VotingEnds.IsZero() && time.Now().After(p.VotingEnds) {
		return ErrVotingExpired
	}

	voterKey := string(v.VoterPubKey)
	if g.voters[v.ProposalID] == nil {
		g.voters[v.ProposalID] = make(map[string]bool)
	}
	if g.voters[v.ProposalID][voterKey] {
		return ErrDuplicateVote
	}

	g.voters[v.ProposalID][voterKey] = true
	g.votes[v.ProposalID] = append(g.votes[v.ProposalID], v)

	// Broadcast via Whisper if available.
	if g.whisperEngine != nil {
		env := governanceEnvelope{Vote: v}
		if data, err := json.Marshal(env); err == nil {
			_ = g.whisperEngine.Publish(governanceTopic, data)
		}
	}

	return nil
}

// Tally returns the vote counts for the given proposal.
func (g *GovernanceRegistry) Tally(proposalID string) (forCount, againstCount, abstainCount int) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, v := range g.votes[proposalID] {
		switch v.Vote {
		case VoteFor:
			forCount++
		case VoteAgainst:
			againstCount++
		case VoteAbstain:
			abstainCount++
		}
	}
	return
}

// GetProposal returns the proposal with the given ID, or ErrProposalNotFound.
func (g *GovernanceRegistry) GetProposal(id string) (*ProtocolProposal, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	p, ok := g.proposals[id]
	if !ok {
		return nil, ErrProposalNotFound
	}
	return p, nil
}

// ListProposals returns all proposals in the registry.
func (g *GovernanceRegistry) ListProposals() []*ProtocolProposal {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*ProtocolProposal, 0, len(g.proposals))
	for _, p := range g.proposals {
		result = append(result, p)
	}
	return result
}

// WithdrawProposal marks a proposal as withdrawn. Only the original author
// (matching AuthorPubKey) may withdraw.
func (g *GovernanceRegistry) WithdrawProposal(id string, authorPubKey []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	p, ok := g.proposals[id]
	if !ok {
		return ErrProposalNotFound
	}
	if string(p.AuthorPubKey) != string(authorPubKey) {
		return ErrInvalidSignature
	}
	if p.Status != StatusActive && p.Status != StatusDraft {
		return ErrVotingClosed
	}
	p.Status = StatusWithdrawn
	return nil
}

// Finalize closes voting on a proposal and sets its status to Passed or Rejected
// based on whether forCount > againstCount.
func (g *GovernanceRegistry) Finalize(proposalID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	p, ok := g.proposals[proposalID]
	if !ok {
		return ErrProposalNotFound
	}
	if p.Status != StatusActive {
		return ErrVotingClosed
	}

	var forCount, againstCount int
	for _, v := range g.votes[proposalID] {
		switch v.Vote {
		case VoteFor:
			forCount++
		case VoteAgainst:
			againstCount++
		}
	}

	if forCount > againstCount {
		p.Status = StatusPassed
	} else {
		p.Status = StatusRejected
	}
	return nil
}
