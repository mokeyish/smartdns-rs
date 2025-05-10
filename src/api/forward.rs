use std::sync::Arc;

use axum::{Json, extract::State, response::IntoResponse};
use byte_unit::rust_decimal::str;

use crate::config::ForwardRule;
use serde::{Deserialize, Serialize};

use super::openapi::{IntoRouter, http::get, routes};
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
            .rule_groups()
            .iter()
            .map(|(n, rules)| ForwardRuleGroup {
                name: n.clone(),
                count: rules.forward_rules.len(),
                forwards: rules.forward_rules.clone(),
            })
            .collect::<Vec<_>>()
            .into_data_list_payload(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForwardRuleGroup {
    name: String,
    count: usize,
    forwards: Vec<ForwardRule>,
}
