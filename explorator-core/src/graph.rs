use std::collections::HashMap;

use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use serde::Serialize;
use uuid::Uuid;

use crate::entity::{Entity, EntityType, RelationKind};

/// The unified recon result: every entity discovered across all pipeline
/// stages, linked by typed relations, stored as a graph internally.
///
/// Nodes are deduplicated by `(entity_type, value)` so that, for example,
/// a subdomain rediscovered by two different plugins collapses into a
/// single node instead of appearing twice in the graph. `source` is kept
/// as whichever plugin discovered the entity first, and `metadata` is
/// merged key-by-key across every plugin that later touches the same
/// entity, so one plugin's enrichment never silently overwrites another's.
#[derive(Default)]
pub struct EntityGraph {
    graph: StableDiGraph<Entity, RelationKind>,
    index: HashMap<Uuid, NodeIndex>,
    /// (entity_type, value) -> node index, for dedup lookups.
    dedup_index: HashMap<(EntityType, String), NodeIndex>,
    /// Relations whose target hadn't been inserted yet at the time the
    /// source entity was added; retried every time a new entity is added.
    pending_edges: Vec<(Uuid, Uuid, RelationKind)>,
}

impl EntityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a single entity, merging into an existing node of the same
    /// `(entity_type, value)` if one is already present. Returns the id of
    /// the resulting node (which may differ from `entity.id` when merged).
    pub fn add_entity(&mut self, entity: Entity) -> Uuid {
        let key = (entity.entity_type, entity.value.clone());
        let relations = entity.relations.clone();

        let final_id = if let Some(&existing_idx) = self.dedup_index.get(&key) {
            let existing = &mut self.graph[existing_idx];
            if entity.confidence > existing.confidence {
                existing.confidence = entity.confidence;
            }
            existing.timestamp = entity.timestamp;
            merge_metadata(&mut existing.metadata, &entity.metadata);
            existing.id
        } else {
            let id = entity.id;
            let idx = self.graph.add_node(entity);
            self.index.insert(id, idx);
            self.dedup_index.insert(key, idx);
            id
        };

        for relation in relations {
            self.pending_edges.push((final_id, relation.target, relation.kind));
        }
        self.resolve_pending_edges();

        final_id
    }

    pub fn add_entities(&mut self, entities: impl IntoIterator<Item = Entity>) {
        for entity in entities {
            self.add_entity(entity);
        }
    }

    fn resolve_pending_edges(&mut self) {
        let mut still_pending = Vec::new();
        for (source, target, kind) in self.pending_edges.drain(..) {
            match (self.index.get(&source), self.index.get(&target)) {
                (Some(&s), Some(&t)) => {
                    self.graph.add_edge(s, t, kind);
                }
                _ => still_pending.push((source, target, kind)),
            }
        }
        self.pending_edges = still_pending;
    }

    pub fn get(&self, id: Uuid) -> Option<&Entity> {
        self.index.get(&id).map(|&idx| &self.graph[idx])
    }

    pub fn len(&self) -> usize {
        self.graph.node_count()
    }

    pub fn is_empty(&self) -> bool {
        self.graph.node_count() == 0
    }

    pub fn entities(&self) -> impl Iterator<Item = &Entity> {
        self.graph.node_weights()
    }

    pub fn entities_by_type(&self, entity_type: EntityType) -> Vec<&Entity> {
        self.graph
            .node_weights()
            .filter(|e| e.entity_type == entity_type)
            .collect()
    }

    pub fn find_by_value(&self, entity_type: EntityType, value: &str) -> Option<&Entity> {
        self.dedup_index
            .get(&(entity_type, value.to_string()))
            .map(|&idx| &self.graph[idx])
    }

    /// Outbound relations for the given entity, as `(kind, target entity)` pairs.
    pub fn relations_of(&self, id: Uuid) -> Vec<(&RelationKind, &Entity)> {
        let Some(&idx) = self.index.get(&id) else {
            return Vec::new();
        };
        self.graph
            .edges(idx)
            .map(|edge| (edge.weight(), &self.graph[edge.target()]))
            .collect()
    }

    /// Snapshot the whole graph as a plain, serializable structure suitable
    /// for the CLI's JSON output and the API's `/results` endpoint.
    pub fn to_snapshot(&self) -> GraphSnapshot {
        let nodes = self.graph.node_weights().cloned().collect();
        let edges = self
            .graph
            .edge_references()
            .map(|edge| EdgeSnapshot {
                source: self.graph[edge.source()].id,
                target: self.graph[edge.target()].id,
                kind: edge.weight().clone(),
            })
            .collect();
        GraphSnapshot { nodes, edges }
    }
}

#[derive(Serialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<Entity>,
    pub edges: Vec<EdgeSnapshot>,
}

#[derive(Serialize)]
pub struct EdgeSnapshot {
    pub source: Uuid,
    pub target: Uuid,
    pub kind: RelationKind,
}

/// Combine `new` into `existing` key-by-key when both are JSON objects,
/// so a later plugin's fields (e.g. whois's `registrar`) don't blow away
/// an earlier plugin's (e.g. certsh's `wildcard`) on the same entity.
/// Falls back to wholesale replacement when either side isn't an object
/// (e.g. the first entity ever inserted, whose metadata may be `null`).
fn merge_metadata(existing: &mut serde_json::Value, new: &serde_json::Value) {
    if new.is_null() {
        return;
    }
    match (existing.as_object_mut(), new.as_object()) {
        (Some(existing_map), Some(new_map)) => {
            for (k, v) in new_map {
                existing_map.insert(k.clone(), v.clone());
            }
        }
        _ => *existing = new.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;

    #[test]
    fn merging_same_entity_combines_metadata_without_clobbering() {
        let mut graph = EntityGraph::new();

        let first = Entity::new(EntityType::Domain, "example.com", "certsh")
            .with_metadata(serde_json::json!({ "wildcard": false }));
        graph.add_entity(first);

        let second = Entity::new(EntityType::Domain, "example.com", "whois")
            .with_metadata(serde_json::json!({ "registrar": "Example Registrar" }));
        graph.add_entity(second);

        let merged = graph
            .find_by_value(EntityType::Domain, "example.com")
            .expect("entity should exist");

        assert_eq!(merged.source, "certsh", "source stays the first discoverer");
        assert_eq!(merged.metadata["wildcard"], serde_json::json!(false));
        assert_eq!(merged.metadata["registrar"], serde_json::json!("Example Registrar"));
        assert_eq!(graph.len(), 1, "dedup should not create a second node");
    }
}
