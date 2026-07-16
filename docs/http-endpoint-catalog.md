# Fixed HTTP endpoint catalogs

The optional
splash_capabilities::http_endpoint_catalog::HttpEndpointCatalog is a narrow
outbound JSON capability for a reviewed, finite set of host-selected HTTP
endpoints. It can inject a host-resolved credential into one fixed HTTPS
endpoint, but it is not a general HTTP client, a general secret-retrieval API,
a proxy, or an operating-system egress sandbox.

Enable the feature explicitly because it links an HTTP/TLS client:

~~~toml
[dependencies]
splash-capabilities = { path = "../splash-capabilities", features = ["http-endpoint-catalog"] }
~~~

For the sealed workflow facade, enable the matching
splash-workflow/http-endpoint-catalog feature.

To resolve endpoint-bound secrets at invocation time from a native credential
store on macOS, iOS, or Windows, enable
`platform-keyring-secret-resolver` instead. That feature includes
`http-endpoint-catalog`; the matching workflow feature forwards it.

~~~toml
[dependencies]
splash-capabilities = { path = "../splash-capabilities", features = ["platform-keyring-secret-resolver"] }
~~~

## Authority model

During trusted Rust setup, the host fixes each complete URL, method, and
opaque identifier:

~~~rust
use splash_capabilities::{
    http_endpoint_catalog::{
        HttpEndpoint, HttpEndpointCatalog, HttpEndpointCatalogLimits, HttpEndpointMethod,
        HttpEndpointSecret, HttpEndpointSecretStore,
    },
    CapabilityRuntime, ToolMetadata, ToolPolicy,
};

fn register_release_status(
    runtime: &mut CapabilityRuntime,
    release_status_token: impl Into<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = HttpEndpointCatalog::new(HttpEndpointCatalogLimits {
        max_entries: 4,
        max_response_bytes: 32 * 1024,
        ..HttpEndpointCatalogLimits::default()
    })?;
    catalog.insert(HttpEndpoint::https(
        "release.status",
        HttpEndpointMethod::Get,
        "https://api.example.com/v1/release/status?channel=stable",
    )?.with_bearer_secret("release.status.token")?)?;

    // This value comes from trusted host setup, such as an OS credential store.
    // It is never supplied to or returned from Splash source.
    let mut secrets = HttpEndpointSecretStore::new();
    secrets.insert(
        "release.status.token",
        HttpEndpointSecret::new(release_status_token)?,
    )?;

    let mut policy = ToolPolicy::json("service.request");
    policy.max_calls = 2;
    policy.max_input_bytes = 4 * 1024;
    policy.max_output_bytes = 32 * 1024;
    runtime.register_http_endpoint_catalog_tool_with_secret_resolver(
        policy,
        ToolMetadata::new("Gets the reviewed release status by opaque identifier."),
        catalog,
        secrets,
    )?;
    Ok(())
}
~~~

Splash can supply only an opaque ID and, for a host-configured POST, one JSON
object or array body:

~~~splash
use mod.tool

let raw = tool.call_json("service.request", {endpoint: "release.status"})
let status = raw.parse_json()
status
~~~

The executable request schema publishes the host-facing opaque ID enum, requires
endpoint, and rejects additional fields before the adapter runs. It never
publishes the URL. The runtime also independently checks the request, so direct
adapter use cannot widen the accepted shape.

The caller supplies `release_status_token` during trusted host setup, such as
from an OS credential store; it is not a Splash function or generated-script
input. Hosts can instead implement `HttpEndpointSecretResolver` to resolve from
a platform credential store for every invocation. The resolver is called only
for a credential binding selected during trusted endpoint setup; Splash cannot
name a secret or invoke a secret resolver directly.

`platform_keyring_secret_resolver::PlatformKeyringSecretResolver` is a
read-only implementation for pre-provisioned native credentials. Each trusted
setup entry maps one opaque endpoint-secret ID to one fixed service/account
locator. It exposes neither mappings nor locators through accessors or `Debug`,
performs no lookup during configuration, and uses only the explicit macOS, iOS,
or Windows keyring implementation. It never creates, updates, rotates, or
deletes a credential. Unsupported Linux and embedded targets fail closed rather
than using keyring-rs's process-local mock store. Stored values must be
nonempty printable ASCII HTTP header values no larger than 4 KiB.

For a host that provisions the credential separately, replace the in-memory
store in the setup example with this resolver:

~~~rust
use splash_capabilities::platform_keyring_secret_resolver::{
    PlatformKeyringSecretEntry, PlatformKeyringSecretResolver,
};

let secrets = PlatformKeyringSecretResolver::new(vec![
    PlatformKeyringSecretEntry::new(
        "release.status.token",
        "com.example.splash",
        "release-status",
    )?,
])?;
runtime.register_http_endpoint_catalog_tool_with_secret_resolver(
    policy,
    ToolMetadata::new("Gets the reviewed release status by opaque identifier."),
    catalog,
    secrets,
)?;
~~~

GET requires exactly {endpoint: "..."}. POST requires
{endpoint: "...", body: {...}} or an array body. The body remains bounded by
the catalog request limit, and the tool policy may lower that input budget but
cannot widen it. Its field semantics are intentionally not inferred from the
remote API. Use separate narrowly named catalog tools, per-step leases, a
trusted input-aware authorizer, or a dedicated schema-checked Rust adapter when
a remote endpoint needs tighter payload rules.

One catalog tool can invoke every entry in its catalog. Use separate tools or a
trusted authorizer when different endpoints need different workflow grants.
The host decides whether to share its host-side catalog descriptor with an LLM;
Splash source has no catalog-discovery API.

## Fixed transport behavior

HttpEndpoint::https accepts only an HTTPS URL with a host, no URL credentials,
and no fragment. The fixed path and query are host configuration. URL length is
bounded to 4 KiB. HttpEndpoint::insecure_http is explicitly named and exists
only for trusted local or development services; do not use it for credentials,
private data, or a production origin policy.

`HttpEndpoint::with_bearer_secret` injects one fixed `Authorization: Bearer`
value, and `with_secret_header` injects a value into one fixed reviewed header.
Both require an HTTPS endpoint. The latter refuses transport-managed,
cookie, and response-shaping header names, so it cannot change the request
method, target, body encoding, proxy behavior, or response format. The secret
identifier and value are host configuration; neither becomes a Splash input.

At execution, the catalog:

- permits only the configured GET or POST;
- disables environment proxies and redirect following;
- exposes no script-selected URL, method, header, query, redirect target, or
  cookie API;
- resolves an endpoint-bound secret only after request schema and input checks,
  then marks its resulting HTTP header sensitive;
- sends Accept: application/json, sends Content-Type: application/json for
  POST, and disables content encoding;
- requires a 2xx response containing a JSON object or array;
- rejects, rather than truncates, oversized headers or response bodies.

The default bounds are 32 endpoints, 16 KiB of script request input, 64 KiB of
raw response data, 16 KiB of response headers, and a 15-second total request
deadline. Hard limits are 128 endpoints, 256 KiB request input, 1 MiB response
data, 64 KiB headers, and 60 seconds. The tool policy can lower input and
output budgets but cannot raise the catalog request or response bounds.

The feature uses ureq with default features disabled and Rustls enabled. The
target build therefore needs the normal native linker/toolchain required by
its TLS dependency.

## Failure and disclosure behavior

Trusted setup receives detailed HttpEndpointCatalogError values. Splash
receives only either HTTP endpoint access was denied for an invalid request or
HTTP endpoint request failed for configuration, transport, status, size, or
response-format failures. URLs, remote status codes, response bodies, headers,
secret identifiers, secret values, and transport details are not released to
script diagnostics.

The endpoint URL has no public accessor and is omitted from Debug. The
published tool contract contains opaque endpoint IDs, not endpoint URLs or
credential bindings. `HttpEndpointSecret` and `HttpEndpointSecretStore` redact
their Debug output and provide no secret getter or iterator. Audit entries
retain the tool name and byte counts, not the endpoint ID, URL, headers,
secret identifiers, secret values, or body.

`PlatformKeyringSecretEntry` and `PlatformKeyringSecretResolver` likewise
redact their native credential mappings and locators. Credential-store errors
remain finite host-side categories and become the same generic failed tool
result as other resolver failures.

## Security boundary

This is API-level mediation only. It stops a generated Splash program from
changing the target of this one catalog tool; it does not prevent the embedding
process or another trusted Rust adapter from opening a network connection. It
also does not pin DNS results, enforce a firewall rule, validate the remote
service's authorization model, protect a host-selected endpoint from later
server-side changes, offer general secret access, guarantee zeroization of
HTTP/TLS implementation buffers, or contain a blocking request that is already
running.

Hosts must treat endpoint setup as trusted policy, keep secrets out of URLs and
tool metadata, keep the resolver's own logs and errors free of secret material,
and run effects needing real egress isolation behind a target-specific
containment or network policy backend. In particular, this catalog is not
sufficient to run untrusted local tools with ambient process authority.
The resolver runs in the local adapter before the HTTP request starts; its own
latency and any platform credential-store behavior are host responsibility and
are not bounded by the catalog's HTTP deadline.

For mobile and embedded applications, pass the catalog to
mobile::MobileRuntimeBuilder::register_http_endpoint_catalog_tool or
splash_workflow::mobile::MobileWorkflowBuilder::register_http_endpoint_catalog_tool
before build(). Use each matching
`register_http_endpoint_catalog_tool_with_secret_resolver` method when the
catalog has a credential binding. Each builder consumes both catalog and
resolver during setup, so dynamic source and workflow steps cannot modify the
catalog or select a secret afterward.
