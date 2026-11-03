//! The bridge from a test's core 0.2 kernel to this crate's core 0.3 file endpoint.
//!
//! `ikigai-web`, `ikigai-json`, `ikigai-engine`, `ikigai-fn` and `ikigai-sparql` have no
//! release on core 0.3 yet, so a test of this crate through one of them has two cores. The
//! old-core crate runs in a kernel of its own, and `urn:file:` there forwards to a real core
//! 0.3 kernel over [`ikigai_fs::space`]. Only bytes, their media type and what the door needs
//! to frame them cross (see the manifest for when this goes). A caller's capability does not
//! cross: every test here issues as root, and the ACL is pinned by the tests on core 0.3.

use std::path::Path;
use std::sync::Arc;

use futures::StreamExt;
use ikigai_core_for_old_modules as old;

/// `space` with `urn:file:` bound, the same template as [`ikigai_fs::space`], over `root`.
pub fn bind_file(space: old::EndpointSpace, root: &Path) -> old::EndpointSpace {
    space.bind(
        old::UriTemplate::parse(ikigai_fs::FILE_TEMPLATE).unwrap(),
        FileBridge(ikigai_core::Kernel::new(Arc::new(ikigai_fs::space(root)))),
    )
}

struct FileBridge(ikigai_core::Kernel);

/// The request as core 0.3 spells it: the bridge serves `Source`, with inline arguments.
fn request(inv: &old::Invocation<'_>) -> old::Result<ikigai_core::Request> {
    if inv.request.verb != old::Verb::Source {
        return Err(old::Error::Endpoint("the bridge only serves Source".into()));
    }
    let target = ikigai_core::Iri::parse(inv.request.target.as_str())
        .map_err(|e| old::Error::Endpoint(e.to_string()))?;
    let mut request = ikigai_core::Request::new(ikigai_core::Verb::Source, target);
    for (name, arg) in &inv.request.args {
        let old::ArgRef::Inline(value) = arg else {
            return Err(old::Error::Endpoint(format!(
                "the bridge only carries inline arguments, not `{name}`"
            )));
        };
        request = request.with_arg(name, ikigai_core::ArgRef::Inline(value.clone()));
    }
    Ok(request)
}

fn repr_type(new: &ikigai_core::ReprType) -> old::ReprType {
    let mut repr_type = old::ReprType::new(new.media_type.as_str());
    for (key, value) in &new.params {
        repr_type = repr_type.with_param(key, value);
    }
    repr_type
}

fn error(new: ikigai_core::Error) -> old::Error {
    match new {
        ikigai_core::Error::NotFound(detail) => old::Error::NotFound(detail),
        ikigai_core::Error::Denied(detail) => old::Error::Denied(detail),
        ikigai_core::Error::InvalidArgument { name, detail } => {
            old::Error::InvalidArgument { name, detail }
        }
        other => old::Error::Endpoint(other.to_string()),
    }
}

fn stream(new: ikigai_core::ByteStream) -> old::ByteStream {
    Box::pin(new.map(|chunk| chunk.map_err(error)))
}

#[async_trait::async_trait]
impl old::Endpoint for FileBridge {
    async fn invoke(&self, inv: &old::Invocation<'_>) -> old::Result<old::Representation> {
        let answer = self
            .0
            .issue(request(inv)?, &ikigai_core::Capability::root())
            .await
            .map_err(error)?;
        Ok(old::Representation::new(
            repr_type(&answer.repr_type),
            answer.bytes,
        ))
    }

    async fn invoke_body(
        &self,
        inv: &old::Invocation<'_>,
    ) -> old::Result<old::Representation<old::Body>> {
        let answer = self
            .0
            .issue_body(request(inv)?, &ikigai_core::Capability::root())
            .await
            .map_err(error)?;
        let body = match answer.bytes {
            ikigai_core::Body::Bytes(bytes) => old::Body::Bytes(bytes),
            ikigai_core::Body::Replay(replay) => old::Body::Replay(Arc::new(ReplayBridge(replay))),
            ikigai_core::Body::Once(once) => old::Body::Once(stream(once)),
        };
        Ok(old::Representation::from_body(
            repr_type(&answer.repr_type),
            body,
        ))
    }
}

/// A core 0.3 file body as a core 0.2 one: the same reads, length and validator.
struct ReplayBridge(Arc<dyn ikigai_core::Replay>);

impl old::Replay for ReplayBridge {
    fn open(&self) -> old::ByteStream {
        stream(self.0.open())
    }

    fn open_at(&self, offset: u64) -> Option<old::ByteStream> {
        self.0.open_at(offset).map(stream)
    }

    fn len_hint(&self) -> Option<u64> {
        self.0.len_hint()
    }

    fn validator(&self) -> Option<old::ContentId> {
        self.0
            .validator()
            .map(|id| old::ContentId::parse(&id.to_string()).unwrap())
    }
}
