use std::sync::Arc;

use axum::{Json, extract::State, response::IntoResponse};

use super::openapi::{IntoRouter, http::get, routes};
use super::{IntoDataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![forwards].into_router()
}

#[get("/forwards")]
async fn forwards(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(
        state
            .app
            .cfg()
            .await
            .forward_rules()
            .clone()
            .into_data_list_payload(),
    )
}
