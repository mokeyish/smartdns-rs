use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

mod address;
mod audit;
mod cache;
mod forward;
mod listener;
mod log;
mod nameserver;
mod serve_dns;
mod settings;

use crate::{app::App, server::DnsHandle};

type StatefulRouter = Router<Arc<ServeState>>;

pub struct ServeState {
    pub app: Arc<App>,
    pub dns_handle: DnsHandle,
}

pub fn routes() -> StatefulRouter {
    Router::new()
        .merge(serve_dns::routes())
        .nest("/api", api_routes())
}

fn api_routes() -> StatefulRouter {
    Router::new()
        .route("/version", get(version))
        .merge(cache::routes())
        .merge(nameserver::routes())
        .merge(address::routes())
        .merge(forward::routes())
        .merge(settings::routes())
        .merge(audit::routes())
        .merge(listener::routes())
        .merge(log::routes())
}

async fn version() -> Json<&'static str> {
    Json(crate::version())
}

struct ApiError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for crate::dns::DnsError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(r#"{{ "error": "{0}" }}"#, self),
        )
            .into_response()
    }
}

#[derive(Deserialize, Serialize)]
struct DataListPayload<T> {
    count: usize,
    data: Vec<T>,
}

impl<T> DataListPayload<T> {
    fn new(data: Vec<T>) -> Self {
        Self {
            count: data.len(),
            data,
        }
    }
}

trait IntoDataListPayload<T> {
    fn into_data_list_payload(self) -> DataListPayload<T>;
}

impl<T> IntoDataListPayload<T> for Vec<T> {
    #[inline]
    fn into_data_list_payload(self) -> DataListPayload<T> {
        DataListPayload::new(self)
    }
}
