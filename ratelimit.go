package main

import (
	"sync"
	"time"
)

// RateLimiter enforces per-IP and per-user connection limits.
// It tracks active connections (not requests/sec) — a connection
// occupies a slot until it's released.
type RateLimiter struct {
	maxPerIP   int
	maxPerUser int

	mu      sync.Mutex
	byIP    map[string]int
	byUser  map[string]int
	stopCh  chan struct{}
}

// NewRateLimiter creates a rate limiter with the specified connection caps.
func NewRateLimiter(maxPerIP, maxPerUser int) *RateLimiter {
	rl := &RateLimiter{
		maxPerIP:   maxPerIP,
		maxPerUser: maxPerUser,
		byIP:       make(map[string]int),
		byUser:     make(map[string]int),
		stopCh:     make(chan struct{}),
	}

	// Periodic cleanup of zero-count entries to prevent unbounded map growth.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.cleanup()
			case <-rl.stopCh:
				return
			}
		}
	}()

	return rl
}

// Stop terminates the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.stopCh:
		// Already stopped.
	default:
		close(rl.stopCh)
	}
}

// Acquire attempts to take a connection slot for the given IP and user.
// Returns true if allowed, false if either limit is exceeded.
func (rl *RateLimiter) Acquire(ip, userID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.byIP[ip] >= rl.maxPerIP {
		return false
	}
	if userID != "" && rl.byUser[userID] >= rl.maxPerUser {
		return false
	}

	rl.byIP[ip]++
	if userID != "" {
		rl.byUser[userID]++
	}
	return true
}

// Release frees a connection slot for the given IP and user.
// Must be called when a connection closes.
func (rl *RateLimiter) Release(ip, userID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.byIP[ip] > 0 {
		rl.byIP[ip]--
	}
	if userID != "" && rl.byUser[userID] > 0 {
		rl.byUser[userID]--
	}
}

// cleanup removes zero-count entries to prevent map growth.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for k, v := range rl.byIP {
		if v <= 0 {
			delete(rl.byIP, k)
		}
	}
	for k, v := range rl.byUser {
		if v <= 0 {
			delete(rl.byUser, k)
		}
	}
}
