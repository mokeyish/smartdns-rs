use std::sync::Arc;

use axum::{Json, extract::State};

use crate::config::NameServerInfo;

use super::openapi::{IntoRouter, http::get, routes};
use super::{DataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![nameservers].into_router()
}

#[get("/nameservers")]
async fn nameservers(
    State(state): State<Arc<ServeState>>,
) -> Json<DataListPayload<NameServerInfo>> {
    let servers = state.app.cfg().await.servers().to_vec();

    Json(servers.into())
}
