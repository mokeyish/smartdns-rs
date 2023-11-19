use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    Router::new().route("/logs/config", get(log_config))
}

async fn log_config(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.log_config()).into_response()
}
