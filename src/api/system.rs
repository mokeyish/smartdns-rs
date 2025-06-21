use super::openapi::{IntoRouter, http::get, routes};
use crate::libdns::proto::rr::Name;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![status,].into_router()
}

#[get("/system/status", description = "Get system status", responses(
    (status = 200, content_type="application/json", body = SystemStatus )
))]
async fn status(State(s): State<Arc<ServeState>>) -> Json<SystemStatus> {
    let app = s.app.clone();
    let cfg = app.cfg().await;
    Json(SystemStatus {
        server_name: cfg.server_name(),
        version: crate::BUILD_VERSION,
        build_date: crate::BUILD_DATE.with_timezone(&chrono::Local),
        uptime: format!("{:?}", app.uptime()),
        config_loaded_at: format!("{:?}", app.loaded_at().await),
        active_queries: app.active_queries(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
struct SystemStatus {
    #[schema(value_type = String)]
    server_name: Name,
    version: &'static str,
    #[schema(value_type = String)]
    build_date: chrono::DateTime<chrono::Local>,
    uptime: String,
    config_loaded_at: String,
    active_queries: usize,
}
