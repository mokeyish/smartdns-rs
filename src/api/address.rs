use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::AddressRule;

use super::openapi::{IntoRouter, http::get, routes};
use super::{IntoDataListPayload, ServeState, StatefulRouter};
use axum::{Json, extract::State, response::IntoResponse};

pub fn routes() -> StatefulRouter {
    routes![addresses].into_router()
}

#[get("/addresses")]
async fn addresses(State(state): State<Arc<ServeState>>) -> impl IntoResponse {
    Json(
        state
            .app
            .cfg()
            .await
            .rule_groups()
            .iter()
            .map(|(n, rules)| AddressRuleGroup {
                name: n.clone(),
                count: rules.address_rules.len(),
                addresses: rules.address_rules.clone(),
            })
            .collect::<Vec<_>>()
            .into_data_list_payload(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AddressRuleGroup {
    name: String,
    count: usize,
    addresses: Vec<AddressRule>,
}
