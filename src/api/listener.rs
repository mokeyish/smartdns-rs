use std::sync::Arc;

use axum::{Json, extract::State, response::IntoResponse};

use super::openapi::{IntoRouter, http::get, routes};
use super::{IntoDataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![listeners].into_router()
}

#[get("/listeners")]
async fn listeners(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(
        state
            .app
            .cfg()
            .await
            .binds()
            .to_vec()
            .into_data_list_payload(),
    )
}
