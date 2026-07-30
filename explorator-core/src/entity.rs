use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The kinds of recon artifacts that flow through the unified data model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Domain,
    Subdomain,
    IpAddress,
    Port,
    Service,
    Technology,
    Url,
    Endpoint,
    Certificate,
    EmailAddress,
    Asn,
    Cidr,
    Vulnerability,
    Screenshot,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EntityType::Domain => "domain",
            EntityType::Subdomain => "subdomain",
            EntityType::IpAddress => "ip_address",
            EntityType::Port => "port",
            EntityType::Service => "service",
            EntityType::Technology => "technology",
            EntityType::Url => "url",
            EntityType::Endpoint => "endpoint",
            EntityType::Certificate => "certificate",
            EntityType::EmailAddress => "email_address",
            EntityType::Asn => "asn",
            EntityType::Cidr => "cidr",
            EntityType::Vulnerability => "vulnerability",
            EntityType::Screenshot => "screenshot",
        };
        f.write_str(s)
    }
}

/// A typed edge between two entities in the recon graph, e.g. a Subdomain
/// `ResolvesTo` an IpAddress, or an IpAddress `HasPort` a Port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    ResolvesTo,
    HasPort,
    RunsService,
    HasVulnerability,
    HasTechnology,
    HasCertificate,
    DiscoveredFrom,
    LinksTo,
    BelongsToAsn,
    BelongsToCidr,
    Custom(String),
}

impl std::fmt::Display for RelationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationKind::ResolvesTo => write!(f, "resolves_to"),
            RelationKind::HasPort => write!(f, "has_port"),
            RelationKind::RunsService => write!(f, "runs_service"),
            RelationKind::HasVulnerability => write!(f, "has_vulnerability"),
            RelationKind::HasTechnology => write!(f, "has_technology"),
            RelationKind::HasCertificate => write!(f, "has_certificate"),
            RelationKind::DiscoveredFrom => write!(f, "discovered_from"),
            RelationKind::LinksTo => write!(f, "links_to"),
            RelationKind::BelongsToAsn => write!(f, "belongs_to_asn"),
            RelationKind::BelongsToCidr => write!(f, "belongs_to_cidr"),
            RelationKind::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// A directed link from the owning entity to another entity by id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub target: Uuid,
    pub kind: RelationKind,
}

impl Relation {
    pub fn new(target: Uuid, kind: RelationKind) -> Self {
        Self { target, kind }
    }
}

/// A single normalized recon artifact. Every plugin output, regardless of
/// which external tool produced it, is converted into one or more `Entity`
/// values before being merged into the pipeline's `EntityGraph`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: Uuid,
    pub entity_type: EntityType,
    /// Primary string representation: a domain name, an IP, a URL, etc.
    pub value: String,
    /// Name of the plugin that produced this entity (e.g. "subfinder").
    pub source: String,
    /// 0.0-1.0 confidence that this entity is accurate / still valid.
    pub confidence: f32,
    /// Unix epoch seconds when the entity was created.
    pub timestamp: u64,
    /// Tool-specific structured detail (headers, DNS records, CVE ids, ...).
    pub metadata: serde_json::Value,
    /// Outbound links to other entities already known at creation time.
    pub relations: Vec<Relation>,
}

impl Entity {
    pub fn new(entity_type: EntityType, value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            entity_type,
            value: value.into(),
            source: source.into(),
            confidence: 1.0,
            timestamp: now(),
            metadata: serde_json::Value::Null,
            relations: Vec::new(),
        }
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_relation(mut self, target: Uuid, kind: RelationKind) -> Self {
        self.relations.push(Relation::new(target, kind));
        self
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
