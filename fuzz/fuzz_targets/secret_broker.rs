#![no_main]

use std::cell::Cell;
use std::convert::Infallible;
use std::rc::Rc;

use libfuzzer_sys::fuzz_target;
use splash_protocol::{CapabilityGrant, ResourceKind, ResourceSelector};
use splash_worker::secret_broker::{CapabilitySecretBroker, SecretAccessBinding, SecretValue};

const MAX_FUZZ_INPUT_BYTES: usize = 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let marker = input_marker(data);
    let malformed_marker = format!("{marker}/");
    let configured = SecretAccessBinding::new("release.publish", "release.token")
        .expect("fixed configured binding is valid");
    let unconfigured = SecretAccessBinding::new("release.publish", "other.token")
        .expect("fixed unconfigured binding is valid");
    let selected = if byte(data, 3) & 1 == 0 {
        configured.clone()
    } else {
        unconfigured
    };

    let calls = Rc::new(Cell::new(0_usize));
    let observed_calls = calls.clone();
    let provider = move |_identifier: &str| -> Result<SecretValue, Infallible> {
        observed_calls.set(observed_calls.get() + 1);
        Ok(SecretValue::new(b"fuzz-secret".to_vec()).expect("fixed secret is bounded"))
    };
    let mut broker = CapabilitySecretBroker::new(provider, [configured.clone()])
        .expect("fixed broker configuration is valid");

    let mut grant = CapabilityGrant::json(match byte(data, 0) % 4 {
        0 => "release.publish".to_owned(),
        1 => "release.read".to_owned(),
        2 => "bad/tool".to_owned(),
        _ => malformed_marker.clone(),
    });
    match byte(data, 1) % 5 {
        0 => {}
        1 => {
            grant.resources.insert(
                ResourceSelector::new(ResourceKind::Secret, "release.token")
                    .expect("fixed resource is valid"),
            );
        }
        2 => {
            grant.resources.insert(
                ResourceSelector::new(ResourceKind::FileRoot, "release.token")
                    .expect("fixed resource is valid"),
            );
        }
        3 => {
            grant.resources.insert(ResourceSelector {
                kind: ResourceKind::Secret,
                id: malformed_marker,
            });
        }
        _ => {
            grant.resources.insert(
                ResourceSelector::new(ResourceKind::Secret, "other.token")
                    .expect("fixed resource is valid"),
            );
        }
    }
    if byte(data, 2) & 1 != 0 {
        grant.max_calls = 0;
    }

    let should_resolve = grant.validate().is_ok()
        && selected == configured
        && grant.tool == selected.tool()
        && grant.resources.iter().any(|resource| {
            resource.kind == ResourceKind::Secret && resource.id == selected.secret_identifier()
        });
    let result = broker.with_secret(&grant, &selected, |secret| secret.len());

    assert_eq!(calls.get(), usize::from(should_resolve));
    assert_eq!(result.is_ok(), should_resolve);
    match result {
        Ok(length) => assert_eq!(length, b"fuzz-secret".len()),
        Err(error) => {
            assert!(!error.to_string().contains(&marker));
            assert!(!format!("{error:?}").contains(&marker));
        }
    }
});

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or_default()
}

fn input_marker(data: &[u8]) -> String {
    let mut marker = String::from("fuzz-");
    for byte in data.iter().take(48) {
        marker.push(char::from(b'a' + byte % 26));
    }
    marker
}
