use std::sync::Arc;

use super::openapi::{http::get, routes, IntoRouter};
use super::{IntoDataListPayload, ServeState, StatefulRouter};
use axum::{extract::State, response::IntoResponse, Json};

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
