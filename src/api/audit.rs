use std::sync::Arc;

use crate::config::AuditConfig;

use super::openapi::{IntoRouter, http::get, routes};
use axum::{Json, extract::State};

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![audit_config,].into_router()
}

#[get("/audits/config", tag = "Audits")]
async fn audit_config(State(state): State<Arc<ServeState>>) -> Json<AuditConfig> {
    let config = state.app.cfg().await.audit_config().clone();
    Json(config)
}
