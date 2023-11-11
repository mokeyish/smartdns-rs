use std::sync::Arc;

use serde::{Deserialize, Serialize};

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use crate::dns_mw_cache::CachedQueryRecord;

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    Router::new()
        .route("/cache", get(get_caches))
        .route("/cache/flush", post(flush_cache))
}

async fn get_caches(State(state): State<Arc<ServeState>>) -> Json<DnsCachePayload> {
    Json(DnsCachePayload::new(
        if let Some(c) = state.app.cache().await {
            c.cached_records().await
        } else {
            vec![]
        },
    ))
}

async fn flush_cache(State(state): State<Arc<ServeState>>) -> StatusCode {
    if let Some(c) = state.app.cache().await {
        c.clear().await;
    }
    StatusCode::NO_CONTENT
}

#[derive(Deserialize, Serialize)]
struct DnsCachePayload {
    count: usize,
    data: Vec<CachedQueryRecord>,
}

impl DnsCachePayload {
    fn new(data: Vec<CachedQueryRecord>) -> Self {
        Self {
            count: data.len(),
            data,
        }
    }
}
