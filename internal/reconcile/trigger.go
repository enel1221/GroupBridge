package reconcile

import (
	"context"
	"time"
)

// waitForTriggerBurst coalesces a burst of lossy event hints before the caller
// drains keyed dirty work. The quiet-period timer reduces API pressure during
// bulk membership edits, while maxDelay prevents a continuous stream from
// postponing access convergence indefinitely.
func waitForTriggerBurst(
	ctx context.Context,
	triggers <-chan struct{},
	stop <-chan struct{},
	settleWindow time.Duration,
	maxDelay time.Duration,
) bool {
	settle := time.NewTimer(settleWindow)
	maximum := time.NewTimer(maxDelay)
	defer settle.Stop()
	defer maximum.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-stop:
			return false
		case <-maximum.C:
			return true
		case <-settle.C:
			return true
		case _, open := <-triggers:
			if !open {
				return true
			}
			if !settle.Stop() {
				select {
				case <-settle.C:
				default:
				}
			}
			settle.Reset(settleWindow)
		}
	}
}
