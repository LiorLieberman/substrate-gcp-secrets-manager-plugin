# substrate-gcp-secrets-manager-plugin

A [substrate](https://github.com/agent-substrate/substrate) credential-provider
plugin backed by Google Cloud Secret Manager.

The plugin implements substrate's `CredentialProvider` gRPC API
(`pkg/proto/credproviderpb`). Given an `ate-secret://secretmanager.googleapis.com/...`
URI, it reads the referenced secret version from Secret Manager and returns its
payload, so secrets stay in Secret Manager and substrate never stores them.

## Endpoint

With the manifests in `config/`, which deploy into substrate's `ate-system`
namespace:

| | |
|---|---|
| Provider name | `secretmanager.googleapis.com`, as in `ate-secret://secretmanager.googleapis.com` |
| Address | `gsm-credential-provider.ate-system.svc:50051` |
| API | `credprovider.CredentialProvider/FetchSecret` over mutual TLS |

The address is the Service's DNS name, which is also the name on the
provider's serving certificate, so callers must use exactly this form.

## Credential URIs

The URI path is the Secret Manager resource name. The version is optional and
defaults to `latest`:

```
ate-secret://secretmanager.googleapis.com/projects/<project>/secrets/<secret>/versions/<version>
ate-secret://secretmanager.googleapis.com/projects/<project>/secrets/<secret>
```

`<version>` is a positive integer or `latest`. Query strings, fragments and
percent-encoding are refused.

## Responses

A secret version's payload is the raw credential value, and `FetchSecret`
returns it verbatim in `opaque_bytes`. When Secret Manager supplies a CRC32C
checksum, the provider verifies the payload against it first.

Failures map to gRPC status codes:

| Condition | Code |
|---|---|
| The URI is malformed or names another provider | `InvalidArgument` |
| The secret or version does not exist, or has no payload | `NotFound` |
| The provider's identity may not access the secret | `PermissionDenied` |
| The payload fails its CRC32C check | `Unavailable` |
| Any other Secret Manager error | `Unavailable` |

## Security model

- **Only one caller identity is admitted.** The provider serves mutual TLS with
  a certificate from substrate's servicedns signer. It admits a caller only if
  the caller's certificate chains to substrate's podidentity trust bundle and
  carries the SPIFFE ID in `--injector-identity`, which defaults to substrate's
  egress gateway.
- **No per-actor authorization yet.** Each request names the actor it is made
  for, and the provider logs it but does not authorize on it. An admitted caller
  can resolve any secret the provider's own identity can read, so grant Secret
  Manager access per secret rather than per project.

## Install

Prerequisites:

- A substrate cluster at v0.2.0 or later. The provider relies on substrate's pod
  certificate controller for its serving certificate and for its callers' trust
  bundle.
- [ko](https://ko.build), which the Makefile runs with `go run`, and a registry
  for `KO_DOCKER_REPO`.

**1. Grant Secret Manager access.** On GKE with Workload Identity Federation,
grant the provider's Kubernetes ServiceAccount access to each secret it serves:

```bash
gcloud secrets add-iam-policy-binding <secret> --project <project> \
  --role roles/secretmanager.secretAccessor \
  --member "principal://iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/<project>.svc.id.goog/subject/ns/ate-system/sa/gsm-credential-provider"
```

**2. Deploy the provider.**

```bash
KO_DOCKER_REPO=<registry> make deploy
kubectl -n ate-system rollout status deployment/gsm-credential-provider
```

For a kind cluster, use its local registry and build only the host
architecture:

```bash
KO_DOCKER_REPO=localhost:5001 KO_DEFAULTPLATFORMS=linux/$(go env GOARCH) make deploy
```

kind has no Workload Identity, so the provider has no Google credentials there
and every fetch fails with `PermissionDenied` until you supply Application
Default Credentials some other way.

**3. Point substrate's egress gateway at the provider.** From a substrate
checkout, redeploy the gateway with credential injection enabled:

```bash
hack/install-ate.sh --deploy-atenet --experimental-egress-credential-injection \
  --credential-provider-name ate-secret://secretmanager.googleapis.com \
  --credential-provider-address gsm-credential-provider.ate-system.svc:50051
```

This adds the `--credential-provider-*` flags to the `ext-proc` container of
the `atenet-egress` Deployment and restarts it. The gateway then dials the
provider over mutual TLS, presenting its podidentity certificate and expecting
the provider's certificate to name the host part of the address. It serves one
provider at a time, so this replaces any provider it used before. To confirm:

```bash
kubectl -n ate-system get deployment atenet-egress -o yaml | grep credential-provider
```

**4. Store a secret.** The payload is the raw value, with no trailing newline:

```bash
printf '%s' "$TOKEN" | gcloud secrets create example-api-token --project <project> --data-file=-
```

Its URI is then
`ate-secret://secretmanager.googleapis.com/projects/<project>/secrets/example-api-token`.

To uninstall, first redeploy the gateway without the provider, then remove
the provider. Removing the provider while the gateway still points at it makes
every credential fetch fail.

```bash
hack/install-ate.sh --deploy-atenet --experimental-use-sdsmint   # from the substrate checkout
make undeploy                                                    # from this repository
```

Keep `--experimental-use-sdsmint` to leave the gateway's TLS interception on;
drop it to turn interception off as well.

`make undeploy` removes the provider's ServiceAccount, Deployment and Service,
and leaves the `ate-system` namespace to substrate.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--listen-address` | `:50051` | gRPC listen address |
| `--health-address` | `:9090` | HTTP address for `/healthz` and `/readyz` |
| `--server-cred-bundle` | required | Serving credential bundle: PKCS#8 key and certificate chain |
| `--client-ca-file` | required | Trust bundle the caller's certificate must chain to |
| `--injector-identity` | `spiffe://cluster.local/ns/ate-system/sa/atenet-egress` | SPIFFE ID the caller's certificate must carry |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--drain-grace` | `5s` | How long in-flight calls may finish on shutdown |

## Development

```bash
make test               # go test -race ./...
make verify             # gofmt, go vet, go mod tidy check
make release-manifest   # manifests with the image pinned by digest
```

The plugin tracks substrate's `credproviderpb` API through the substrate module
version in `go.mod`. `internal/credbundle` is a copy of substrate's pod
certificate bundle loader, which a separate module cannot import.
