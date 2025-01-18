use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};

use super::openapi::{http::get, routes, IntoRouter};
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
            .listeners()
            .to_vec()
            .into_data_list_payload(),
    )
}
