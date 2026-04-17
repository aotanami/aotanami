/*
Copyright 2026 Zelyo AI
*/

package events

import (
	"sync"
	"testing"
	"time"
)

func TestBusPublishAndRecent(t *testing.T) {
	b := NewBus(5)

	for i := 0; i < 7; i++ {
		b.Publish(&Event{Type: "t", Stage: StageScan})
	}

	recent := b.Recent("", 10)
	if len(recent) != 5 {
		t.Fatalf("expected 5 retained events (capacity), got %d", len(recent))
	}
}

func TestBusRecentStageFilter(t *testing.T) {
	b := NewBus(50)
	b.Publish(&Event{Type: "a", Stage: StageScan})
	b.Publish(&Event{Type: "b", Stage: StageFix})
	b.Publish(&Event{Type: "c", Stage: StageScan})

	got := b.Recent(StageScan, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 scan events, got %d", len(got))
	}
	for _, e := range got {
		if e.Stage != StageScan {
			t.Fatalf("unexpected stage %q", e.Stage)
		}
	}
}

func TestBusSubscribeReceivesEvents(t *testing.T) {
	b := NewBus(10)
	ch, cancel := b.Subscribe()
	defer cancel()

	var got Event
	done := make(chan struct{})
	go func() {
		got = <-ch
		close(done)
	}()

	b.Publish(&Event{Type: "x", Stage: StageFix})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive event")
	}
	if got.Type != "x" {
		t.Fatalf("got %q, want x", got.Type)
	}
}

func TestBusSlowSubscriberDropsInsteadOfBlocking(t *testing.T) {
	b := NewBus(10)
	_, cancel := b.Subscribe() // never read
	defer cancel()

	// Publishing 500 events on a full unread 64-buffer channel must not block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			b.Publish(&Event{Type: "flood"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber — must be non-blocking")
	}
}

func TestConcurrentPublishAndSubscribe(t *testing.T) {
	b := NewBus(100)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Publish(&Event{Type: "concurrent"})
			}
		}()
	}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, cancel := b.Subscribe()
			defer cancel()
			for k := 0; k < 10; k++ {
				select {
				case <-ch:
				case <-time.After(100 * time.Millisecond):
				}
			}
		}()
	}
	wg.Wait()

	if n := len(b.Recent("", 10)); n == 0 {
		t.Fatal("expected buffer to contain recent events")
	}
}

func TestReductionPct(t *testing.T) {
	cases := []struct {
		source, result, want int
	}{
		{100, 10, 90},
		{10, 10, 0},
		{0, 0, 0},
		{50, 25, 50},
	}
	for _, c := range cases {
		if got := reductionPct(c.source, c.result); got != c.want {
			t.Errorf("reductionPct(%d,%d) = %d, want %d", c.source, c.result, got, c.want)
		}
	}
}

func TestSeverityLevel(t *testing.T) {
	if severityLevel("Critical") != LevelError {
		t.Fatal("Critical should map to LevelError")
	}
	if severityLevel("medium") != LevelWarning {
		t.Fatal("medium should map to LevelWarning")
	}
	if severityLevel("low") != LevelInfo {
		t.Fatal("low should map to LevelInfo")
	}
}
