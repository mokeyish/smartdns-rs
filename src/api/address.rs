use std::sync::Arc;

use super::openapi::{IntoRouter, http::get, routes};
use super::{IntoDataListPayload, ServeState, StatefulRouter};
use axum::{Json, extract::State, response::IntoResponse};

pub fn routes() -> StatefulRouter {
    routes![addresses].into_router()
}

#[get("/addresses")]
async fn addresses(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(
        state
            .app
            .cfg()
            .await
            .address_rules()
            .clone()
            .into_data_list_payload(),
    )
}
