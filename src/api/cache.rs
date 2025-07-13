use std::sync::Arc;

use super::openapi::{
    IntoRouter,
    http::{get, post},
    routes,
};
use super::{ServeState, StatefulRouter};
use crate::{api::DataListPayload, config::CacheConfig, dns_mw_cache::CachedQueryRecord, log};
use axum::{Json, extract::State, http::StatusCode};

pub fn routes() -> StatefulRouter {
    let r1 = routes![flush, caches].into_router();
    let r2 = routes![config].into_router();
    r1.merge(r2)

    // routes![flush, caches, config].into_router()
}

#[get("/caches", tag = "Caches", operation_id = "list_caches")]
async fn caches(State(state): State<Arc<ServeState>>) -> Json<DataListPayload<CachedQueryRecord>> {
    let caches = if let Some(c) = state.app.cache().await {
        c.cached_records().await
    } else {
        vec![]
    };
    Json(caches.into())
}

#[post("/caches/flush", tag = "Caches", operation_id = "flush_caches")]
async fn flush(State(state): State<Arc<ServeState>>) -> StatusCode {
    if let Some(c) = state.app.cache().await {
        c.clear().await;
    }
    log::info!("flushed cache");
    StatusCode::NO_CONTENT
}

#[get("/caches/config", tag = "Caches", operation_id = "get_cache_config")]
async fn config(State(state): State<Arc<ServeState>>) -> Json<CacheConfig> {
    let config = state.app.cfg().await.cache_config().clone();
    Json(config)
}
