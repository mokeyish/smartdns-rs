use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};

use super::{IntoDataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    Router::new().route("/nameservers", get(nameservers))
}

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
