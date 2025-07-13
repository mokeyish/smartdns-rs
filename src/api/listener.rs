use std::sync::Arc;

use super::openapi::{IntoRouter, http::get, routes};
use super::{DataListPayload, ServeState, StatefulRouter};
use crate::config::BindAddrConfig;
use axum::{Json, extract::State};

pub fn routes() -> StatefulRouter {
    routes![listeners].into_router()
}

#[get("/listeners")]
async fn listeners(State(state): State<Arc<ServeState>>) -> Json<DataListPayload<BindAddrConfig>> {
    let binds = state.app.cfg().await.binds().to_vec();
    Json(binds.into())
}
