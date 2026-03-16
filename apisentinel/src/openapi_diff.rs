//! Semantic diffing for OpenAPI / AsyncAPI YAML specs.
//!
//! Parses both specs as serde_yaml::Value trees and walks the structure
//! to detect meaningful API changes: new/removed endpoints, parameter
//! changes, auth changes, schema changes, and enum changes.

use serde_yaml::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct SemanticChange {
    pub category: ChangeCategory,
    pub path: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeCategory {
    EndpointAdded,
    EndpointRemoved,
    ParameterChanged,
    AuthChanged,
    RequestSchemaChanged,
    ResponseSchemaChanged,
    EnumChanged,
    OtherChanged,
}

impl std::fmt::Display for ChangeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointAdded => write!(f, "ENDPOINT_ADDED"),
            Self::EndpointRemoved => write!(f, "ENDPOINT_REMOVED"),
            Self::ParameterChanged => write!(f, "PARAMETER_CHANGED"),
            Self::AuthChanged => write!(f, "AUTH_CHANGED"),
            Self::RequestSchemaChanged => write!(f, "REQUEST_SCHEMA_CHANGED"),
            Self::ResponseSchemaChanged => write!(f, "RESPONSE_SCHEMA_CHANGED"),
            Self::EnumChanged => write!(f, "ENUM_CHANGED"),
            Self::OtherChanged => write!(f, "OTHER_CHANGED"),
        }
    }
}

/// Diff two YAML spec strings and return semantic changes.
pub fn diff_specs(old_yaml: &str, new_yaml: &str) -> Vec<SemanticChange> {
    let old: Value = match serde_yaml::from_str(old_yaml) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let new: Value = match serde_yaml::from_str(new_yaml) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut changes = Vec::new();

    diff_paths(&old, &new, &mut changes);
    diff_security(&old, &new, &mut changes);
    diff_schemas(&old, &new, &mut changes);

    changes
}

/// Compare paths (endpoints) between old and new specs.
fn diff_paths(old: &Value, new: &Value, changes: &mut Vec<SemanticChange>) {
    let old_paths = get_mapping(old, "paths");
    let new_paths = get_mapping(new, "paths");

    // Also check "channels" for AsyncAPI
    let old_channels = get_mapping(old, "channels");
    let new_channels = get_mapping(new, "channels");

    diff_endpoint_set(&old_paths, &new_paths, "paths", changes);
    diff_endpoint_set(&old_channels, &new_channels, "channels", changes);
}

fn diff_endpoint_set(
    old_set: &BTreeSet<String>,
    new_set: &BTreeSet<String>,
    prefix: &str,
    changes: &mut Vec<SemanticChange>,
) {
    for path in new_set.difference(old_set) {
        changes.push(SemanticChange {
            category: ChangeCategory::EndpointAdded,
            path: format!("{prefix}/{path}"),
            description: format!("New endpoint added: {path}"),
        });
    }
    for path in old_set.difference(new_set) {
        changes.push(SemanticChange {
            category: ChangeCategory::EndpointRemoved,
            path: format!("{prefix}/{path}"),
            description: format!("Endpoint removed: {path}"),
        });
    }

    // For endpoints present in both, check method-level details
    // Endpoints present in both are diffed at method level by diff_path_details.
}

/// Walk method-level details for shared paths.
fn diff_path_details(
    old: &Value,
    new: &Value,
    container_key: &str,
    changes: &mut Vec<SemanticChange>,
) {
    let old_container = match old.get(container_key) {
        Some(v) => v,
        None => return,
    };
    let new_container = match new.get(container_key) {
        Some(v) => v,
        None => return,
    };

    let old_map = as_mapping(old_container);
    let new_map = as_mapping(new_container);

    for (path_key, old_path_val) in &old_map {
        let Some(new_path_val) = new_map.get(path_key) else {
            continue; // removal already caught
        };
        let old_methods = as_mapping(old_path_val);
        let new_methods = as_mapping(new_path_val);

        for (method, old_method_val) in &old_methods {
            let Some(new_method_val) = new_methods.get(method) else {
                continue;
            };

            // Check parameters
            let old_params = old_method_val.get("parameters");
            let new_params = new_method_val.get("parameters");
            if old_params != new_params {
                changes.push(SemanticChange {
                    category: ChangeCategory::ParameterChanged,
                    path: format!("{container_key}/{path_key}/{method}/parameters"),
                    description: format!("Parameters changed for {method} {path_key}"),
                });
            }

            // Check requestBody
            let old_body = old_method_val.get("requestBody");
            let new_body = new_method_val.get("requestBody");
            if old_body != new_body {
                changes.push(SemanticChange {
                    category: ChangeCategory::RequestSchemaChanged,
                    path: format!("{container_key}/{path_key}/{method}/requestBody"),
                    description: format!("Request body changed for {method} {path_key}"),
                });
            }

            // Check responses
            let old_resp = old_method_val.get("responses");
            let new_resp = new_method_val.get("responses");
            if old_resp != new_resp {
                changes.push(SemanticChange {
                    category: ChangeCategory::ResponseSchemaChanged,
                    path: format!("{container_key}/{path_key}/{method}/responses"),
                    description: format!("Responses changed for {method} {path_key}"),
                });
            }

            // Check security at method level
            let old_sec = old_method_val.get("security");
            let new_sec = new_method_val.get("security");
            if old_sec != new_sec {
                changes.push(SemanticChange {
                    category: ChangeCategory::AuthChanged,
                    path: format!("{container_key}/{path_key}/{method}/security"),
                    description: format!("Auth requirements changed for {method} {path_key}"),
                });
            }
        }
    }
}

/// Compare top-level security / securitySchemes.
fn diff_security(old: &Value, new: &Value, changes: &mut Vec<SemanticChange>) {
    // Top-level security
    if old.get("security") != new.get("security") {
        changes.push(SemanticChange {
            category: ChangeCategory::AuthChanged,
            path: "security".into(),
            description: "Top-level security requirements changed".into(),
        });
    }

    // securitySchemes under components
    let old_schemes = old
        .get("components")
        .and_then(|c| c.get("securitySchemes"));
    let new_schemes = new
        .get("components")
        .and_then(|c| c.get("securitySchemes"));
    if old_schemes != new_schemes {
        changes.push(SemanticChange {
            category: ChangeCategory::AuthChanged,
            path: "components/securitySchemes".into(),
            description: "Security schemes definition changed".into(),
        });
    }

    // Also diff path-level detail
    diff_path_details(old, new, "paths", changes);
    diff_path_details(old, new, "channels", changes);
}

/// Compare component schemas and detect enum changes.
fn diff_schemas(old: &Value, new: &Value, changes: &mut Vec<SemanticChange>) {
    let old_schemas = old.get("components").and_then(|c| c.get("schemas"));
    let new_schemas = new.get("components").and_then(|c| c.get("schemas"));

    let (Some(old_s), Some(new_s)) = (old_schemas, new_schemas) else {
        if old_schemas != new_schemas {
            changes.push(SemanticChange {
                category: ChangeCategory::OtherChanged,
                path: "components/schemas".into(),
                description: "Component schemas section added or removed".into(),
            });
        }
        return;
    };

    let old_map = as_mapping(old_s);
    let new_map = as_mapping(new_s);

    let old_keys: BTreeSet<_> = old_map.keys().collect();
    let new_keys: BTreeSet<_> = new_map.keys().collect();

    for k in new_keys.difference(&old_keys) {
        changes.push(SemanticChange {
            category: ChangeCategory::OtherChanged,
            path: format!("components/schemas/{k}"),
            description: format!("New schema added: {k}"),
        });
    }
    for k in old_keys.difference(&new_keys) {
        changes.push(SemanticChange {
            category: ChangeCategory::OtherChanged,
            path: format!("components/schemas/{k}"),
            description: format!("Schema removed: {k}"),
        });
    }

    // Check each shared schema for enum changes
    for k in old_keys.intersection(&new_keys) {
        let ov = &old_map[*k];
        let nv = &new_map[*k];
        if ov == nv {
            continue;
        }
        // Check for enum changes at top level of this schema
        let old_enum = ov.get("enum");
        let new_enum = nv.get("enum");
        if old_enum != new_enum && (old_enum.is_some() || new_enum.is_some()) {
            changes.push(SemanticChange {
                category: ChangeCategory::EnumChanged,
                path: format!("components/schemas/{k}/enum"),
                description: format!("Enum values changed in schema {k}"),
            });
        }
        // Check properties for nested enum changes
        check_property_enums(ov, nv, &format!("components/schemas/{k}"), changes);

        // Generic diff if schema changed at all
        if old_enum == new_enum {
            changes.push(SemanticChange {
                category: ChangeCategory::OtherChanged,
                path: format!("components/schemas/{k}"),
                description: format!("Schema modified: {k}"),
            });
        }
    }
}

fn check_property_enums(
    old: &Value,
    new: &Value,
    base_path: &str,
    changes: &mut Vec<SemanticChange>,
) {
    let old_props = as_mapping_opt(old.get("properties"));
    let new_props = as_mapping_opt(new.get("properties"));

    let (Some(op), Some(np)) = (old_props, new_props) else {
        return;
    };

    for (prop_name, old_val) in &op {
        let Some(new_val) = np.get(prop_name) else {
            continue;
        };
        let oe = old_val.get("enum");
        let ne = new_val.get("enum");
        if oe != ne && (oe.is_some() || ne.is_some()) {
            changes.push(SemanticChange {
                category: ChangeCategory::EnumChanged,
                path: format!("{base_path}/properties/{prop_name}/enum"),
                description: format!("Enum values changed in property {prop_name}"),
            });
        }
    }
}

// ── helpers ──

fn get_mapping(doc: &Value, key: &str) -> BTreeSet<String> {
    doc.get(key)
        .and_then(|v| v.as_mapping())
        .map(|m| {
            m.keys()
                .filter_map(|k| k.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn as_mapping(val: &Value) -> std::collections::BTreeMap<String, &Value> {
    val.as_mapping()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| k.as_str().map(|s| (s.to_string(), v)))
                .collect()
        })
        .unwrap_or_default()
}

fn as_mapping_opt(val: Option<&Value>) -> Option<std::collections::BTreeMap<String, &Value>> {
    val.and_then(|v| v.as_mapping()).map(|m| {
        m.iter()
            .filter_map(|(k, v)| k.as_str().map(|s| (s.to_string(), v)))
            .collect()
    })
}

/// Compute a semantic hash from the spec: sorted paths + schema keys.
/// Used for quick equality check that ignores formatting.
pub fn semantic_hash(yaml_content: &str) -> Option<String> {
    let doc: Value = serde_yaml::from_str(yaml_content).ok()?;
    let mut parts = Vec::new();

    // Paths
    if let Some(paths) = doc.get("paths").and_then(|v| v.as_mapping()) {
        let mut keys: Vec<_> = paths.keys().filter_map(|k| k.as_str()).collect();
        keys.sort();
        for k in keys {
            parts.push(format!("path:{k}"));
            if let Some(methods) = paths.get(k).and_then(|v| v.as_mapping()) {
                let mut mkeys: Vec<_> = methods.keys().filter_map(|k| k.as_str()).collect();
                mkeys.sort();
                for m in mkeys {
                    parts.push(format!("  method:{m}"));
                }
            }
        }
    }

    // Channels (AsyncAPI)
    if let Some(channels) = doc.get("channels").and_then(|v| v.as_mapping()) {
        let mut keys: Vec<_> = channels.keys().filter_map(|k| k.as_str()).collect();
        keys.sort();
        for k in keys {
            parts.push(format!("channel:{k}"));
        }
    }

    // Schemas
    if let Some(schemas) = doc
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|v| v.as_mapping())
    {
        let mut keys: Vec<_> = schemas.keys().filter_map(|k| k.as_str()).collect();
        keys.sort();
        for k in keys {
            parts.push(format!("schema:{k}"));
        }
    }

    let joined = parts.join("\n");
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(joined.as_bytes());
    Some(format!("{:x}", hash))
}
