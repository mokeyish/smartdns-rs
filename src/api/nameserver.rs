use std::sync::Arc;

use axum::{Json, extract::State, response::IntoResponse};

use super::openapi::{IntoRouter, http::get, routes};
use super::{IntoDataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![nameservers].into_router()
}

#[get("/nameservers")]
async fn nameservers(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(
        state
            .app
            .cfg()
            .await
            .servers()
            .to_vec()
            .into_data_list_payload(),
    )
}
