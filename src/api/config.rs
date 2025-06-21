use super::openapi::{IntoRouter, http::post, routes};
use super::{ApiError, ServeState, StatefulRouter};
use axum::extract::State;
use std::sync::Arc;

pub fn routes() -> StatefulRouter {
    routes![reload].into_router()
}

#[post("/config/reload")]
async fn reload(State(state): State<Arc<ServeState>>) -> Result<(), ApiError> {
    state.app.reload().await?;
    Ok(())
}
