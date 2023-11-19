use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use super::{IntoDataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    Router::new()
        .route("/caches", get(caches))
        .route("/caches/config", get(cache_config))
        .route("/caches/flush", post(flush_cache))
}

async fn caches(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(
        (if let Some(c) = state.app.cache().await {
            c.cached_records().await
        } else {
            vec![]
        })
        .into_data_list_payload(),
    )
}

async fn flush_cache(State(state): State<Arc<ServeState>>) -> StatusCode {
    if let Some(c) = state.app.cache().await {
        c.clear().await;
    }
    StatusCode::NO_CONTENT
}

async fn cache_config(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.cache_config()).into_response()
}
