use std::sync::Arc;

use super::openapi::{IntoRouter, http::get, routes};
use axum::{Json, extract::State, response::IntoResponse};

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![audit_config,].into_router()
}

#[get("/audits/config")]
async fn audit_config(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.audit_config()).into_response()
}
