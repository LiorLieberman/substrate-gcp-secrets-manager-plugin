// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// /healthz passes whether or not the server is ready, so a draining pod is not
// restarted; /readyz follows the ready flag.
func TestHealthHandler(t *testing.T) {
	var ready atomic.Bool
	h := healthHandler(&ready)

	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	if got := get("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz before ready = %d, want 200", got)
	}
	if got := get("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz before ready = %d, want 503", got)
	}

	ready.Store(true)
	if got := get("/readyz"); got != http.StatusOK {
		t.Errorf("/readyz when ready = %d, want 200", got)
	}

	ready.Store(false)
	if got := get("/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("/readyz while draining = %d, want 503", got)
	}
	if got := get("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz while draining = %d, want 200", got)
	}
}

// run refuses to start without the TLS material, before it dials anything or
// binds a port.
func TestRunRequiresTLSFlags(t *testing.T) {
	tests := []struct {
		name         string
		serverBundle string
		clientCAFile string
		wantErr      string
	}{
		{name: "no server bundle", clientCAFile: "/ca.pem", wantErr: "--server-cred-bundle"},
		{name: "no client CA", serverBundle: "/bundle.pem", wantErr: "--client-ca-file"},
		{name: "client CA unreadable", serverBundle: "/bundle.pem", clientCAFile: filepath.Join(t.TempDir(), "absent.pem"), wantErr: "server credentials"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origBundle, origCA := *serverBundle, *clientCAFile
			t.Cleanup(func() { *serverBundle, *clientCAFile = origBundle, origCA })
			*serverBundle, *clientCAFile = tc.serverBundle, tc.clientCAFile

			err := run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("run() error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildVersionPrefersExplicitVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "v9.9.9"
	if got := buildVersion(); !strings.HasPrefix(got, "v9.9.9") {
		t.Errorf("buildVersion() = %q, want it to start with v9.9.9", got)
	}
	version = ""
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() is empty without an explicit version")
	}
}
