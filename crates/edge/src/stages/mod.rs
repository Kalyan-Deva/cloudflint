pub mod origin;

use crate::pipeline::{Pipeline, Stage};

/// The request path, in order. Rate limiting, the WAF and the cache slot in ahead of
/// the origin as they land - the origin stage stays last because it always answers.
pub fn build() -> Pipeline {
    Pipeline::new(vec![Box::new(origin::Origin::new()) as Box<dyn Stage>])
}
