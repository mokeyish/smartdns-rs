use super::openapi::{
    IntoRouter,
    http::{get, post},
    routes,
};
use super::{ApiError, ServeState, StatefulRouter};
use crate::libdns::proto::rr::Name;
use axum::Json;
use axum::extract::State;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub fn routes() -> StatefulRouter {
    let r1 = routes![reload].into_router();
    let r2 = routes![config].into_router();
    r1.merge(r2)
    // routes![reload, config].into_router()
}

#[post("/config/reload", tag = "Config")]
async fn reload(State(state): State<Arc<ServeState>>) -> Result<(), ApiError> {
    state.app.reload().await?;
    Ok(())
}

#[get("/config", tag = "Config", operation_id = "config")]
async fn config(State(state): State<Arc<ServeState>>) -> Json<ServerConfig> {
    let cfg = state.app.cfg().await;
    let conf_dir = cfg
        .conf_dir()
        .map(|p| std::fs::canonicalize(p).unwrap_or(p.to_path_buf()))
        .map(|p| p.to_string_lossy().into_owned());

    Json(ServerConfig {
        server_name: cfg.server_name(),
        conf_dir,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
struct ServerConfig {
    #[schema(value_type = String)]
    server_name: Name,
    conf_dir: Option<String>,
}
