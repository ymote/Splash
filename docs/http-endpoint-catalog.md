# Fixed HTTP endpoint catalogs

The optional
splash_capabilities::http_endpoint_catalog::HttpEndpointCatalog is a narrow
outbound JSON capability for a reviewed, finite set of host-selected HTTP
endpoints. It is not a general HTTP client, a secret broker, a proxy, or an
operating-system egress sandbox.

Enable the feature explicitly because it links an HTTP/TLS client:

~~~toml
[dependencies]
splash-capabilities = { path = "../splash-capabilities", features = ["http-endpoint-catalog"] }
~~~

For the sealed workflow facade, enable the matching
splash-workflow/http-endpoint-catalog feature.

## Authority model

During trusted Rust setup, the host fixes each complete URL, method, and
opaque identifier:

~~~rust
use splash_capabilities::{
    http_endpoint_catalog::{
        HttpEndpoint, HttpEndpointCatalog, HttpEndpointCatalogLimits, HttpEndpointMethod,
    },
    CapabilityRuntime, ToolMetadata, ToolPolicy,
};

fn register_release_status(
    runtime: &mut CapabilityRuntime,
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
    )?)?;

    let mut policy = ToolPolicy::json("service.request");
    policy.max_calls = 2;
    policy.max_input_bytes = 4 * 1024;
    policy.max_output_bytes = 32 * 1024;
    runtime.register_http_endpoint_catalog_tool(
        policy,
        ToolMetadata::new("Gets the reviewed release status by opaque identifier."),
        catalog,
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

At execution, the catalog:

- permits only the configured GET or POST;
- disables environment proxies and redirect following;
- exposes no script-selected URL, method, header, query, redirect target, or
  cookie API;
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
and transport details are not released to script diagnostics.

The endpoint URL has no public accessor and is omitted from Debug. The
published tool contract contains opaque IDs, not endpoint URLs. Audit entries
retain the tool name and byte counts, not the endpoint ID, URL, headers, or
body.

## Security boundary

This is API-level mediation only. It stops a generated Splash program from
changing the target of this one catalog tool; it does not prevent the embedding
process or another trusted Rust adapter from opening a network connection. It
also does not pin DNS results, enforce a firewall rule, validate the remote
service's authorization model, protect a host-selected endpoint from later
server-side changes, broker credentials, or contain a blocking request that is
already running.

Hosts must treat endpoint setup as trusted policy, keep secrets out of URLs and
tool metadata, and run effects needing real egress isolation behind a
target-specific containment or network policy backend. In particular, this
catalog is not sufficient to run untrusted local tools with ambient process
authority.

For mobile and embedded applications, pass the catalog to
mobile::MobileRuntimeBuilder::register_http_endpoint_catalog_tool or
splash_workflow::mobile::MobileWorkflowBuilder::register_http_endpoint_catalog_tool
before build(). Each builder consumes it during setup, so dynamic source and
workflow steps cannot modify the catalog afterward.
