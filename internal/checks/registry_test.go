package checks

import (
	"testing"

	"github.com/asscor/asscor/internal/model"
)

// TestUserCheckIDPrefix locks the reserved prefix separating configuration-
// defined user checks from builtin platform checks.
func TestUserCheckIDPrefix(t *testing.T) {
	if UserCheckIDPrefix != "CU-" {
		t.Errorf("UserCheckIDPrefix = %q, want CU-", UserCheckIDPrefix)
	}
}

// TestRegisterDuplicateIDSkipped verifies the registry refuses to overwrite an
// already-registered ID: a duplicate registration is dropped, not appended.
func TestRegisterDuplicateIDSkipped(t *testing.T) {
	Unregister("DUP-001")
	defer Unregister("DUP-001")

	Register(model.CheckItem{ID: "DUP-001", Name: "first", Domain: model.DomainAttackSurface, Source: model.CheckSourceBuiltin})
	Register(model.CheckItem{ID: "DUP-001", Name: "second", Domain: model.DomainOperationTrust, Source: model.CheckSourceUser})

	item, ok := GetByID("DUP-001")
	if !ok {
		t.Fatal("DUP-001 should be registered")
	}
	if item.Name != "first" {
		t.Errorf("duplicate registration overwrote the original: got name %q, want first", item.Name)
	}
	if GetByDomain(model.DomainAttackSurface) == nil {
		t.Error("registry should retain the original item")
	}
}

// TestRegisterUserCheckCannotOverrideBuiltin is the core separation guarantee:
// a user-defined check that somehow collides with a builtin ID (e.g. "AS-001")
// must not replace the builtin — the registry drops the duplicate.
func TestRegisterUserCheckCannotOverrideBuiltin(t *testing.T) {
	Unregister("AS-COLLIDE")
	defer Unregister("AS-COLLIDE")

	builtin := model.CheckItem{ID: "AS-COLLIDE", Name: "builtin", Domain: model.DomainAttackSurface, Source: model.CheckSourceBuiltin}
	Register(builtin)

	// Attempt to inject a user check with the same ID.
	Register(model.CheckItem{ID: "AS-COLLIDE", Name: "malicious-user", Domain: model.DomainResilience, Source: model.CheckSourceUser})

	got, ok := GetByID("AS-COLLIDE")
	if !ok {
		t.Fatal("AS-COLLIDE should still be registered")
	}
	if got.Name != "builtin" || got.Source != model.CheckSourceBuiltin {
		t.Errorf("user check overwrote builtin: got %+v", got)
	}
}

// TestCheckItemSourceZeroValueIsBuiltin documents that the zero value of the
// Source field means builtin (backward compatible with existing constructors).
func TestCheckItemSourceZeroValueIsBuiltin(t *testing.T) {
	item := model.CheckItem{ID: "X-001"}
	if item.Source == model.CheckSourceUser {
		t.Error("zero-value Source must not be user")
	}
}
