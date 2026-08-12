package mitreengage

import (
	"testing"
)

func TestDeceptionPlansCoverage(t *testing.T) {
	// Every intent must have a "good enough" deception plan.
	for _, intent := range []Intent{
		IntentLateralMovement,
		IntentCredentialAccess,
		IntentExfiltration,
		IntentWebExploit,
		IntentDiscovery,
	} {
		if _, ok := deceptionPlans[intent]; !ok {
			t.Errorf("missing deception plan for intent %s", intent)
		}
	}
}

func TestIntentGuiderGuideIdempotent(t *testing.T) {
	g := NewIntentGuider(t.TempDir())
	defer g.RemoveAll()

	// Fake ports via ephemeral to avoid conflicts in tests.
	g.honey.Stop()
	g.honey = NewHoneypot(nil)

	_, err := g.Guide(nil, IntentCredentialAccess)
	if err != nil {
		t.Fatalf("Guide error: %v", err)
	}

	// Second guide for the same intent is a no-op (idempotent).
	if _, err := g.Guide(nil, IntentCredentialAccess); err != nil {
		t.Fatalf("second Guide error: %v", err)
	}

	// Decoys were deployed (credential intent drops 2 tokens).
	if len(g.tokens.Decoys()) != 2 {
		t.Errorf("expected 2 decoys for credential intent, got %d", len(g.tokens.Decoys()))
	}
}

func TestIntentGuiderUnknownIntentFallsBack(t *testing.T) {
	g := NewIntentGuider(t.TempDir())
	defer g.RemoveAll()
	g.honey.Stop()
	g.honey = NewHoneypot(nil)

	res, err := g.Guide(nil, "unknown_intent")
	if err != nil {
		t.Fatalf("Guide error: %v", err)
	}
	if res.Intent != "unknown_intent" {
		t.Errorf("expected intent passthrough, got %s", res.Intent)
	}
	// Unknown intent falls back to discovery plan (5 scan ports).
	if len(res.Ports) != 5 {
		t.Errorf("expected discovery fallback (5 ports), got %d", len(res.Ports))
	}
}
