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

// Package mtls builds the mutual-TLS credentials a substrate credential
// provider serves with. The provider presents its serving certificate and
// admits a caller only when the caller's certificate both chains to the
// client trust bundle and carries the expected identity as a URI SAN, so no
// other workload that CA trusts can fetch secrets. Both files are reloaded
// when they rotate, without a restart.
package mtls

import (
	"crypto/tls"
	"errors"
	"fmt"

	"google.golang.org/grpc/credentials"

	"github.com/LiorLieberman/substrate-gcp-secrets-manager-plugin/internal/credbundle"
)

// Config names the files and caller identity ServerCredentials serves with.
type Config struct {
	// ServerBundle is the credential bundle presented to callers: a PKCS#8
	// PRIVATE KEY block followed by the certificate chain.
	ServerBundle string
	// ClientCAFile is the trust bundle a caller's certificate must chain to.
	ClientCAFile string
	// CallerIdentity is the URI SAN a caller's certificate must carry.
	CallerIdentity string
}

// ServerCredentials returns gRPC server credentials that require TLS 1.3 and a
// client certificate satisfying cfg. It fails when a field is empty or the
// client trust bundle cannot be read, so a missing projection fails the pod at
// startup rather than on the first call.
func ServerCredentials(cfg Config) (credentials.TransportCredentials, error) {
	switch {
	case cfg.ServerBundle == "":
		return nil, errors.New("a server credential bundle is required")
	case cfg.ClientCAFile == "":
		return nil, errors.New("a client trust bundle is required")
	case cfg.CallerIdentity == "":
		return nil, errors.New("a caller identity is required")
	}

	loadPool := credbundle.PoolLoader(cfg.ClientCAFile)
	if _, err := loadPool(); err != nil {
		return nil, err
	}
	serverCert := credbundle.Loader(cfg.ServerBundle)
	verifySAN := verifyCallerSAN(cfg.CallerIdentity)

	// GetConfigForClient builds the config anew per connection: a certificate
	// signed by a newly published CA verifies without a restart.
	return credentials.NewTLS(&tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := loadPool()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:       tls.VersionTLS13,
				GetCertificate:   serverCert,
				ClientAuth:       tls.RequireAndVerifyClientCert,
				ClientCAs:        pool,
				VerifyConnection: verifySAN,
			}, nil
		},
	}), nil
}

// verifyCallerSAN returns a TLS VerifyConnection callback that accepts a caller
// only when its certificate carries expectedSAN as a URI SAN.
func verifyCallerSAN(expectedSAN string) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("client certificate is required")
		}
		leaf := state.PeerCertificates[0]
		for _, u := range leaf.URIs {
			if u.String() == expectedSAN {
				return nil
			}
		}
		return fmt.Errorf("client certificate URI SANs %v do not include the expected caller identity %q", leaf.URIs, expectedSAN)
	}
}
