package integrity

import "sync/atomic"

var (
	signingEnabled  int32 = 1
	algoVerifyEnabled int32 = 1
	antiDebugEnabled  int32
)

// EnableSigning toggles HMAC signing of assessment results.
// Default: true. Set to false to disable signature generation.
func EnableSigning(on bool) {
	if on {
		atomic.StoreInt32(&signingEnabled, 1)
	} else {
		atomic.StoreInt32(&signingEnabled, 0)
	}
}

// IsSigningEnabled returns whether assessment result signing is active.
func IsSigningEnabled() bool {
	return atomic.LoadInt32(&signingEnabled) == 1
}

// EnableAlgoVerify toggles SSAM/Prism algorithm constant integrity verification.
// Default: true. Set to false to skip the verification check at startup.
func EnableAlgoVerify(on bool) {
	if on {
		atomic.StoreInt32(&algoVerifyEnabled, 1)
	} else {
		atomic.StoreInt32(&algoVerifyEnabled, 0)
	}
}

// IsAlgoVerifyEnabled returns whether algorithm integrity verification is active.
func IsAlgoVerifyEnabled() bool {
	return atomic.LoadInt32(&algoVerifyEnabled) == 1
}

// EnableAntiDebug toggles the anti-debug self-check on Linux.
// Default: false. Set to true to enable TracerPid detection at startup.
func EnableAntiDebug(on bool) {
	if on {
		atomic.StoreInt32(&antiDebugEnabled, 1)
	} else {
		atomic.StoreInt32(&antiDebugEnabled, 0)
	}
}

// IsAntiDebugEnabled returns whether anti-debug detection is active.
func IsAntiDebugEnabled() bool {
	return atomic.LoadInt32(&antiDebugEnabled) == 1
}
