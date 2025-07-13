use std::sync::Arc;

use axum::{Json, extract::State};
use byte_unit::rust_decimal::str;

use crate::config::ForwardRule;
use serde::{Deserialize, Serialize};

use super::openapi::{IntoRouter, http::get, routes};
use super::{DataListPayload, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![forwards].into_router()
}

#[get("/forwards", tag = "Forwards")]
async fn forwards(State(state): State<Arc<ServeState>>) -> Json<DataListPayload<ForwardRuleGroup>> {
    let forwards = state
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
        .collect::<Vec<_>>();

    Json(forwards.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForwardRuleGroup {
    name: String,
    count: usize,
    forwards: Vec<ForwardRule>,
}
