use std::sync::Arc;

use super::openapi::{
    IntoRouter,
    http::{get, post},
    routes,
};
use super::{IntoDataListPayload, ServeState, StatefulRouter};
use crate::log;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

pub fn routes() -> StatefulRouter {
    let route1 = routes![flush_cache, caches].into_router();
    let route2 = routes![cache_config].into_router();
    route1.merge(route2)

    // routes![flush_cache, caches, cache_config].into_router()
}

#[get("/caches")]
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

#[post("/caches/flush")]
async fn flush_cache(State(state): State<Arc<ServeState>>) -> StatusCode {
    if let Some(c) = state.app.cache().await {
        c.clear().await;
    }
    log::info!("flushed cache");
    StatusCode::NO_CONTENT
}

#[get("/caches/config")]
async fn cache_config(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(state.app.cfg().await.cache_config()).into_response()
}
