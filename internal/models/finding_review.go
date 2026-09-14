package models

import (
	"fmt"
	"strings"
	"time"
)

type FindingState string

const (
	FindingStateOpen           FindingState = "open"
	FindingStateInReview       FindingState = "in_review"
	FindingStateConfirmed      FindingState = "confirmed"
	FindingStateFalsePositive  FindingState = "false_positive"
	FindingStateAcceptedRisk   FindingState = "accepted_risk"
	FindingStateRemediated     FindingState = "remediated"
	FindingStateVerified       FindingState = "verified"
)

// ValidateFindingStateTransition ensures that transitions adhere to the security review lifecycle.
func ValidateFindingStateTransition(from, to FindingState) error {
	from = FindingState(strings.ToLower(string(from)))
	to = FindingState(strings.ToLower(string(to)))

	if from == to {
		return nil
	}

	validTransitions := map[FindingState][]FindingState{
		FindingStateOpen: {
			FindingStateInReview, FindingStateConfirmed, FindingStateFalsePositive, FindingStateAcceptedRisk,
		},
		FindingStateInReview: {
			FindingStateConfirmed, FindingStateFalsePositive, FindingStateAcceptedRisk, FindingStateOpen,
		},
		FindingStateConfirmed: {
			FindingStateRemediated, FindingStateAcceptedRisk, FindingStateInReview,
		},
		FindingStateRemediated: {
			FindingStateVerified, FindingStateOpen, FindingStateInReview,
		},
		FindingStateFalsePositive: {
			FindingStateOpen, FindingStateInReview,
		},
		FindingStateAcceptedRisk: {
			FindingStateOpen, FindingStateInReview,
		},
		FindingStateVerified: {
			FindingStateOpen, // Regression / reopened
		},
	}

	allowed, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("invalid current finding state %q", from)
	}
	for _, target := range allowed {
		if target == to {
			return nil
		}
	}
	return fmt.Errorf("disallowed transition from %q to %q", from, to)
}

// FindingAuditTransition represents an immutable audit log of a finding's review lifecycle.
type FindingAuditTransition struct {
	ID            string       `json:"id"`
	FindingID     int64        `json:"finding_id"`
	FromState     FindingState `json:"from_state"`
	ToState       FindingState `json:"to_state"`
	Actor         string       `json:"actor"`
	Justification string       `json:"justification"`
	Timestamp     time.Time    `json:"timestamp"`
}
