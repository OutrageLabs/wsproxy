package main

import (
	"testing"
)

func TestRateLimiter_PerIP(t *testing.T) {
	rl := NewRateLimiter(2, 100)

	if !rl.Acquire("1.2.3.4", "user1") {
		t.Error("first acquire should succeed")
	}
	if !rl.Acquire("1.2.3.4", "user1") {
		t.Error("second acquire should succeed")
	}
	if rl.Acquire("1.2.3.4", "user1") {
		t.Error("third acquire should fail (IP limit = 2)")
	}

	// Different IP should work.
	if !rl.Acquire("5.6.7.8", "user1") {
		t.Error("different IP should succeed")
	}

	// Release one and try again.
	rl.Release("1.2.3.4", "user1")
	if !rl.Acquire("1.2.3.4", "user1") {
		t.Error("acquire after release should succeed")
	}
}

func TestRateLimiter_PerUser(t *testing.T) {
	rl := NewRateLimiter(100, 2)

	if !rl.Acquire("1.1.1.1", "user1") {
		t.Error("first acquire should succeed")
	}
	if !rl.Acquire("2.2.2.2", "user1") {
		t.Error("second acquire should succeed")
	}
	if rl.Acquire("3.3.3.3", "user1") {
		t.Error("third acquire should fail (user limit = 2)")
	}

	// Different user should work.
	if !rl.Acquire("3.3.3.3", "user2") {
		t.Error("different user should succeed")
	}
}

func TestRateLimiter_NoUser(t *testing.T) {
	rl := NewRateLimiter(2, 2)

	// Empty user ID should skip user limiting.
	if !rl.Acquire("1.1.1.1", "") {
		t.Error("first acquire should succeed")
	}
	if !rl.Acquire("1.1.1.1", "") {
		t.Error("second acquire should succeed")
	}
	if rl.Acquire("1.1.1.1", "") {
		t.Error("third acquire should fail (IP limit)")
	}
}

func TestRateLimiter_TrackedKeyCaps(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.maxTrackedIPs = 2
	rl.maxTrackedUsers = 2

	if !rl.Acquire("1.1.1.1", "u1") {
		t.Fatal("first unique key should succeed")
	}
	if !rl.Acquire("2.2.2.2", "u2") {
		t.Fatal("second unique key should succeed")
	}
	if rl.Acquire("3.3.3.3", "u3") {
		t.Fatal("third unique key should fail due tracked-key cap")
	}

	rl.Release("1.1.1.1", "u1")
	rl.cleanup()
	if !rl.Acquire("3.3.3.3", "u3") {
		t.Fatal("new key should succeed after cleanup frees capacity")
	}
}
