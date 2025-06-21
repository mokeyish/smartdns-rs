use std::sync::Arc;

use super::openapi::{IntoRouter, http::get, routes};
use super::{ServeState, StatefulRouter};
use axum::{Json, extract::State, response::IntoResponse};

pub fn routes() -> StatefulRouter {
    routes![log_config].into_router()
}

#[get("/logs/config")]
async fn log_config(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.log_config()).into_response()
}
