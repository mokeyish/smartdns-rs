use std::sync::Arc;

use super::openapi::{http::get, routes, IntoRouter};
use super::{ServeState, StatefulRouter};
use axum::{extract::State, response::IntoResponse, Json};

pub fn routes() -> StatefulRouter {
    routes![server_name].into_router()
}

#[get("/server-name", responses(
    (status = 200, description = "Server Name", content_type="application/json", body = String )
))]
async fn server_name(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.server_name())
}
