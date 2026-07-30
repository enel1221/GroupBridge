package reconcile

import (
	"context"
	"testing"
	"time"
)

func TestWaitForTriggerBurstUsesAQuietPeriod(t *testing.T) {
	triggers := make(chan struct{}, 1)
	stop := make(chan struct{})
	done := make(chan bool, 1)
	started := time.Now()

	go func() {
		done <- waitForTriggerBurst(
			context.Background(),
			triggers,
			stop,
			40*time.Millisecond,
			500*time.Millisecond,
		)
	}()

	time.Sleep(20 * time.Millisecond)
	triggers <- struct{}{}

	select {
	case <-done:
		t.Fatal("burst returned before the quiet period after the newest hint")
	case <-time.After(30 * time.Millisecond):
	}

	select {
	case proceed := <-done:
		if !proceed {
			t.Fatal("burst wait stopped instead of requesting reconciliation")
		}
		if elapsed := time.Since(started); elapsed < 55*time.Millisecond || elapsed > 200*time.Millisecond {
			t.Fatalf("burst elapsed = %s, want a bounded quiet-period delay", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("burst did not settle")
	}
}

func TestWaitForTriggerBurstHasMaximumLatency(t *testing.T) {
	triggers := make(chan struct{}, 1)
	stop := make(chan struct{})
	done := make(chan bool, 1)
	started := time.Now()

	go func() {
		done <- waitForTriggerBurst(
			context.Background(),
			triggers,
			stop,
			200*time.Millisecond,
			60*time.Millisecond,
		)
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case proceed := <-done:
			if !proceed {
				t.Fatal("burst wait stopped instead of requesting reconciliation")
			}
			if elapsed := time.Since(started); elapsed < 45*time.Millisecond || elapsed > 180*time.Millisecond {
				t.Fatalf("burst elapsed = %s, want maximum latency near 60ms", elapsed)
			}
			return
		case <-ticker.C:
			select {
			case triggers <- struct{}{}:
			default:
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatal("continuous hints postponed reconciliation beyond maximum latency")
		}
	}
}

func TestWaitForTriggerBurstStopsWithoutReconciling(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	if waitForTriggerBurst(context.Background(), make(chan struct{}), stop, time.Second, 2*time.Second) {
		t.Fatal("stopped burst requested reconciliation")
	}
}
