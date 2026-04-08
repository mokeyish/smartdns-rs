use std::sync::Arc;

use anyhow::anyhow;
use serde::Deserialize;

use crate::{
    config::{
        AddressRule, Domain,
        parser::{ConfigFile, ConfigItem, ConfigLine},
    },
    third_ext::serde_str,
};

use super::openapi::{
    IntoRouter, ToSchema,
    http::{delete, get, post, put},
    routes,
};
use super::{ApiError, DataListPayload, ServeState, StatefulRouter};
use axum::{Json, extract::State, http::StatusCode};

pub fn routes() -> StatefulRouter {
    routes![list, create, update, delete].into_router()
}

#[get("/addresses", tag = "Addresses")]
async fn list(State(state): State<Arc<ServeState>>) -> Json<DataListPayload<AddressRule>> {
    let groups = state
        .app
        .cfg()
        .await
        .rule_groups()
        .get("default")
        .map(|group| group.address_rules.clone())
        .unwrap_or_default();

    Json(groups.into())
}

#[post("/addresses", tag = "Addresses")]
async fn create(
    State(state): State<Arc<ServeState>>,
    Json(input): Json<CreateAddressRule>,
) -> Result<StatusCode, ApiError> {
    let rule = input.rule;
    let cfg = state.app.cfg().await;
    let Some(managed_dir) = cfg.managed_dir() else {
        return Err(ApiError::NotFound("managed_dir not found".to_string()));
    };
    if !managed_dir.exists() {
        std::fs::create_dir_all(managed_dir)?;
    }
    let file = managed_dir.join("address.conf");
    if file.exists() {
        let text = std::fs::read_to_string(&file)?;
        let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

        let rules = config
            .iter()
            .enumerate()
            .flat_map(|(i, c)| match c {
                ConfigLine::Config {
                    config: ConfigItem::Address(rule),
                    ..
                } => Some((i, rule.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

        let idx = rules
            .iter()
            .find(|r| r.1.domain == rule.domain)
            .map(|(i, _)| *i);

        if idx.is_some() {
            return Err(anyhow!("address already exists"))?;
        } else {
            config.push(ConfigLine::Config {
                config: ConfigItem::Address(rule),
                comment: None,
            });
        };

        std::fs::write(&file, format!("{config}"))?;
    } else {
        let config = ConfigItem::Address(rule);
        std::fs::write(&file, format!("{config}"))?;
    }

    state.app.reload().await?;

    Ok(StatusCode::CREATED)
}

#[put("/addresses", tag = "Addresses")]
async fn update() {}

#[delete("/addresses", tag = "Addresses")]
async fn delete(
    State(state): State<Arc<ServeState>>,
    Json(input): Json<DeleteAddressRule>,
) -> Result<StatusCode, ApiError> {
    let domain = input.domain;

    let cfg = state.app.cfg().await;
    let Some(managed_dir) = cfg.managed_dir() else {
        return Err(ApiError::NotFound("managed_dir not found".to_string()));
    };

    if !managed_dir.exists() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }
    let file = managed_dir.join("address.conf");
    if !file.exists() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }

    let text = std::fs::read_to_string(&file)?;
    let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

    let idx = config
        .iter()
        .enumerate()
        .flat_map(|(i, c)| match c {
            ConfigLine::Config {
                config: ConfigItem::Address(rule),
                ..
            } if rule.domain == domain => Some(i),
            _ => None,
        })
        .collect::<Vec<_>>();

    if idx.is_empty() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }

    for i in idx.iter().rev() {
        config.remove(*i);
    }

    std::fs::write(&file, format!("{config}"))?;
    state.app.reload().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
struct CreateAddressRule {
    rule: AddressRule,
}

#[derive(Debug, Deserialize, ToSchema)]
struct DeleteAddressRule {
    #[serde(with = "serde_str")]
    #[schema(value_type = String)]
    domain: Domain,
}
