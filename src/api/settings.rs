use std::sync::Arc;

use super::openapi::{IntoRouter, http::get, routes};
use super::{ServeState, StatefulRouter};
use axum::{Json, extract::State, response::IntoResponse};

pub fn routes() -> StatefulRouter {
    routes![server_name].into_router()
}

#[get("/server-name", responses(
    (status = 200, description = "Server Name", content_type="application/json", body = String )
))]
async fn server_name(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.server_name())
}
