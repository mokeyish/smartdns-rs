use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    Router::new().route("/audits/config", get(audit_config))
}

async fn audit_config(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.audit_config()).into_response()
}
