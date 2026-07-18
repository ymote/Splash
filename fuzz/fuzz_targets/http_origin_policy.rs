#![no_main]

use libfuzzer_sys::fuzz_target;
use splash_capabilities::http_endpoint_catalog::{
    HttpEndpointCatalogLimits, HttpEndpointMethod, HttpOrigin, HttpOriginCatalog,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let candidate = String::from_utf8_lossy(data).into_owned();
    for (identifier, method, https) in [
        ("https-origin", HttpEndpointMethod::Get, true),
        ("http-origin", HttpEndpointMethod::Post, false),
    ] {
        let result = if https {
            HttpOrigin::https(identifier, method, candidate.clone())
        } else {
            HttpOrigin::insecure_http(identifier, method, candidate.clone())
        };
        if let Ok(origin) = result {
            assert_eq!(origin.identifier(), identifier);
            assert_eq!(origin.method(), method);

            let mut catalog = HttpOriginCatalog::new(HttpEndpointCatalogLimits {
                max_entries: 1,
                ..HttpEndpointCatalogLimits::default()
            })
            .expect("fixed origin catalog limits are valid");
            catalog
                .insert(origin)
                .expect("one valid origin fits the fixed catalog");
            assert_eq!(catalog.len(), 1);
        }
    }
});
