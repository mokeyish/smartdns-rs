use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};

use super::openapi::{http::get, routes, IntoRouter};
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
