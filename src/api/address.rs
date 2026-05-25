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

    Ok(StatusCode::CREATED)
}

#[put("/addresses", tag = "Addresses")]
async fn update(
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

    // File exists, read and replace
    if file.exists() {
        let text = std::fs::read_to_string(&file)?;
        let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

        // Remove all existing entries with the same domain
        let idxs = config
            .iter()
            .enumerate()
            .flat_map(|(i, c)| match c {
                ConfigLine::Config {
                    config: ConfigItem::Address(r),
                    ..
                } if r.domain == rule.domain => Some(i),
                _ => None,
            })
            .collect::<Vec<_>>();

        for i in idxs.iter().rev() {
            config.remove(*i);
        }

        // Add new entry
        config.push(ConfigLine::Config {
            config: ConfigItem::Address(rule),
            comment: None,
        });

        std::fs::write(&file, format!("{config}"))?;
    } else {
        // File does not exist, create new one like POST
        let config = ConfigItem::Address(rule);
        std::fs::write(&file, format!("{config}"))?;
    }

    Ok(StatusCode::OK)
}

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
        std::fs::create_dir_all(&managed_dir)?;
    }

    let file = managed_dir.join("address.conf");

    // Check whether the domain exists in the static config
    let static_exists = state
        .app
        .cfg()
        .await
        .rule_groups()
        .get("default")
        .map(|group| group.address_rules.iter().any(|r| r.domain == domain))
        .unwrap_or(false);

    // File exists, parse ConfigFile
    if file.exists() {
        let text = std::fs::read_to_string(&file)?;
        let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

        let zero = "0.0.0.0".parse().unwrap();

        // 1. Delete ALL managed entries (including negation)
        let before = config.len();
        config.retain(|line| {
            match line {
                ConfigLine::Config {
                    config: ConfigItem::Address(rule),
                    ..
                } => rule.domain != domain,
                _ => true,
            }
        });
        let managed_deleted = config.len() != before;

        // 2. If something was deleted, DONE (and DO NOT create a new negation as we anted to delete it on purpose)
        if managed_deleted {
            std::fs::write(&file, format!("{config}"))?;
            return Ok(StatusCode::NO_CONTENT);
        }

        // 3. If nothing was deleted, but static exists, create negation
        if static_exists {
            let neg_exists = config.iter().any(|line| {
                match line {
                    ConfigLine::Config {
                        config: ConfigItem::Address(rule),
                        ..
                    } => rule.domain == domain && rule.address == zero,
                    _ => false,
                }
            });

            if !neg_exists {
                config.push(ConfigLine::Config {
                    config: ConfigItem::Address(AddressRule {
                        domain,
                        address: zero,
                    }),
                    comment: Some("negated static rule"),
                });
            }

            std::fs::write(&file, format!("{config}"))?;
            return Ok(StatusCode::NO_CONTENT);
        }

        // 4. Neither static nor managed, return 404
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }

    // File does NOT exist
    if static_exists {
        // Negate static rule, write single rule
        let config = ConfigItem::Address(AddressRule {
            domain,
            address: "0.0.0.0".parse().unwrap(),
        });

        std::fs::write(&file, format!("{config}"))?;
        return Ok(StatusCode::NO_CONTENT);
    }

    // Neither static nor managed, return 404
    Err(ApiError::NotFound(format!("Domain {domain} not found")))
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
