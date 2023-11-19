use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    Router::new().route("/server-name", get(server_name))
}

async fn server_name(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.server_name())
}
