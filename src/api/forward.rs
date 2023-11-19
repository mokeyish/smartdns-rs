use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};

use super::{IntoDataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    Router::new().route("/forwards", get(forwards))
}

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
