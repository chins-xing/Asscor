package cli

import "testing"

// TestCliPeerAllowed verifies the CLI socket peer UID policy: root (0) and
// the kernel's own account are allowed; any other UID is rejected.
func TestCliPeerAllowed(t *testing.T) {
	const kernelEUID = 1001 // e.g. asscor user

	allowed := []uint32{0, kernelEUID}
	for _, uid := range allowed {
		if !cliPeerAllowed(uid, kernelEUID) {
			t.Errorf("uid %d should be allowed", uid)
		}
	}

	rejected := []uint32{1000, 1002, 65534} // other users / nobody
	for _, uid := range rejected {
		if cliPeerAllowed(uid, kernelEUID) {
			t.Errorf("uid %d should be rejected", uid)
		}
	}
}
