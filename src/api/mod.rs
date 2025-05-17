use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use cfg_if::cfg_if;
use http::{HeaderValue, header};
use openapi::Router;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;

mod address;
mod audit;
mod cache;
mod forward;
mod listener;
mod log;
mod nameserver;
mod openapi;
mod serve_dns;
mod settings;

use crate::{app::App, server::DnsHandle};

type StatefulRouter = Router<Arc<ServeState>>;

pub struct ServeState {
    pub app: Arc<App>,
    pub dns_handle: DnsHandle,
}

pub fn routes() -> axum::Router<Arc<ServeState>> {
    use utoipa::openapi::InfoBuilder;
    let (router, mut openapi) = Router::new()
        .merge(serve_dns::routes())
        .nest("/api", api_routes())
        .split_for_parts();
    openapi.info = InfoBuilder::new()
        .title(crate::NAME)
        .version(crate::version())
        .build();

    let router = {
        cfg_if! {
            if #[cfg(feature = "swagger-ui-cdn")]
            {
                router.merge(openapi::swagger_cdn("/api/docs", "/api/openapi.json", openapi, None))
            }
            else if #[cfg(feature = "swagger-ui-embed")]
            {
                use utoipa_swagger_ui::{Config, SwaggerUi};
                router.merge(
                    SwaggerUi::new("/api/docs")
                        .config(
                            Config::default()
                                .show_extensions(true)
                                .show_common_extensions(true)
                                .use_base_layout(),
                        )
                        .url("/api/openapi.json", openapi),
                )
            } else {
                router
            }
        }
    };

    router.layer(
        ServiceBuilder::new().layer(SetResponseHeaderLayer::overriding(
            header::SERVER,
            HeaderValue::from_static(crate::NAME),
        )),
    )
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
struct DataPayload<T> {
    data: T,
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
