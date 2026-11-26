/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

// devServer builds the app, then serves dist/ on localhost:8080 with
// file-watching that triggers a rebuild when any .go file changes.
func devServer() error {
	// Initial build.
	if err := buildApp(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Start file watcher in the background.
	go watchAndRebuild(ctx)

	// Serve dist/ directory.
	addr := "localhost:8080"
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("dist")))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Printf("Dev server running at http://%s\n", addr)
	fmt.Println("Watching for .go file changes (polling every 2s)...")
	fmt.Println("Press Ctrl+C to stop.")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		fmt.Println("\nShutting down dev server...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// watchAndRebuild polls for .go file changes every 2 seconds and triggers
// a rebuild when modifications are detected.
func watchAndRebuild(ctx context.Context) {
	modTimes := make(map[string]time.Time)

	// Seed initial modification times.
	collectModTimes(modTimes)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if hasChanges(modTimes) {
				fmt.Println("\nChange detected, rebuilding...")
				if err := buildApp(); err != nil {
					fmt.Printf("Build error: %v\n", err)
				} else {
					fmt.Println("Rebuild complete. Reload your browser.")
				}
			}
		}
	}
}

// collectModTimes walks the current directory for .go files and records
// their modification times.
func collectModTimes(modTimes map[string]time.Time) {
	// The walk skips every entry it cannot read, so Walk's own error can only
	// be the root's; the next poll walks again, so it is not kept.
	_ = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Skip dist/ and hidden directories.
		if info.IsDir() {
			name := info.Name()
			if name == "dist" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			modTimes[path] = info.ModTime()
		}
		return nil
	})
}

// hasChanges checks whether any .go file has been modified, added, or
// removed since the last check. Updates modTimes in place.
func hasChanges(modTimes map[string]time.Time) bool {
	current := make(map[string]time.Time)
	collectModTimes(current)

	changed := false

	// Check for new or modified files.
	for path, modTime := range current {
		prev, ok := modTimes[path]
		if !ok || !prev.Equal(modTime) {
			changed = true
			break
		}
	}

	// Check for deleted files.
	if !changed {
		for path := range modTimes {
			if _, ok := current[path]; !ok {
				changed = true
				break
			}
		}
	}

	// Update modTimes to current state.
	for k := range modTimes {
		delete(modTimes, k)
	}
	for k, v := range current {
		modTimes[k] = v
	}

	return changed
}
