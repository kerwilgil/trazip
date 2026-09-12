// Package osint provides the entity graph model for OSINT Intelligence.
package osint

import (
	"errors"
	"fmt"
	"sync"
)



// EntityGraphError wraps graph operation errors.
type EntityGraphError struct {
	Op  string
	Err error
}

func (e *EntityGraphError) Error() string {
	return fmt.Sprintf("entitygraph: %s: %v", e.Op, e.Err)
}

func (e *EntityGraphError) Unwrap() error { return e.Err }

// IsEntityGraphError reports whether err is an EntityGraphError.
func IsEntityGraphError(err error) bool {
	var eg *EntityGraphError
	return errors.As(err, &eg)
}

// EntityGraph holds entities and relations with deterministic ordering.
type EntityGraph struct {
	mu            sync.RWMutex
	entities      map[string]Entity
	relations     map[string]EntityRelation
	byKind        map[EntityKind][]string
	byFrom        map[string][]string
	byTo          map[string][]string
	byRelationID  map[string]string // relation ID -> relation key
	maxEntities   int
	maxRelations  int
}

// NewEntityGraph creates an empty entity graph with default bounds.
func NewEntityGraph() *EntityGraph {
	return NewEntityGraphWithBounds(DefaultMaxEntities, DefaultMaxRelations)
}

// NewEntityGraphWithBounds creates an empty entity graph with custom bounds.
func NewEntityGraphWithBounds(maxEntities, maxRelations int) *EntityGraph {
	if maxEntities <= 0 {
		maxEntities = DefaultMaxEntities
	}
	if maxRelations <= 0 {
		maxRelations = DefaultMaxRelations
	}
	return &EntityGraph{
		entities:     make(map[string]Entity),
		relations:    make(map[string]EntityRelation),
		byKind:       make(map[EntityKind][]string),
		byFrom:       make(map[string][]string),
		byTo:         make(map[string][]string),
		byRelationID: make(map[string]string),
		maxEntities:  maxEntities,
		maxRelations: maxRelations,
	}
}

// AddEntity adds an entity to the graph. If an entity with the same ID exists
// and is identical, it is a no-op (idempotent). If it differs, an error is returned.
func (g *EntityGraph) AddEntity(e Entity) error {
	if err := e.Validate(); err != nil {
		return &EntityGraphError{Op: "AddEntity", Err: err}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if existing, ok := g.entities[e.ID]; ok {
		if !entitiesEqual(existing, e) {
			return &EntityGraphError{Op: "AddEntity", Err: fmt.Errorf("entity %q already exists with different content", e.ID)}
		}
		return nil
	}

	if len(g.entities) >= g.maxEntities {
		return &EntityGraphError{Op: "AddEntity", Err: fmt.Errorf("entity limit reached (%d)", g.maxEntities)}
	}

	cloned := e.clone()
	g.entities[e.ID] = cloned
	g.byKind[cloned.Kind] = append(g.byKind[cloned.Kind], e.ID)
	return nil
}

// AddRelation adds a relation to the graph. Validates from/to exist, evidence class,
// and no duplicate relation with same from/to/kind/id. Returns error if validation fails.
// Enforces global relation ID uniqueness: same ID with different content is rejected.
func (g *EntityGraph) AddRelation(r EntityRelation) error {
	if err := r.Validate(); err != nil {
		return &EntityGraphError{Op: "AddRelation", Err: err}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.entities[r.From]; !ok {
		return &EntityGraphError{Op: "AddRelation", Err: fmt.Errorf("from entity %q does not exist", r.From)}
	}
	if _, ok := g.entities[r.To]; !ok {
		return &EntityGraphError{Op: "AddRelation", Err: fmt.Errorf("to entity %q does not exist", r.To)}
	}

	// Check global relation ID uniqueness
	if existingKey, idExists := g.byRelationID[r.ID]; idExists {
		// ID already exists — check if content is identical (idempotent) or conflicting
		if existingRel, ok := g.relations[existingKey]; ok {
			if relationsEqual(existingRel, r) {
				return nil // idempotent
			}
		}
		return &EntityGraphError{Op: "AddRelation", Err: fmt.Errorf("relation ID %q already exists with different content", r.ID)}
	}

	key := relationKey(r.ID, r.From, r.To, r.Kind)
	if _, exists := g.relations[key]; exists {
		return &EntityGraphError{Op: "AddRelation", Err: fmt.Errorf("relation %q already exists", key)}
	}

	if len(g.relations) >= g.maxRelations {
		return &EntityGraphError{Op: "AddRelation", Err: fmt.Errorf("relation limit reached (%d)", g.maxRelations)}
	}

	cloned := r.clone()
	g.relations[key] = cloned
	g.byFrom[r.From] = append(g.byFrom[r.From], key)
	g.byTo[r.To] = append(g.byTo[r.To], key)
	g.byRelationID[r.ID] = key
	return nil
}

// Entity returns a copy of the entity by ID.
func (g *EntityGraph) Entity(id string) (Entity, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	e, ok := g.entities[id]
	if !ok {
		return Entity{}, false
	}
	return e.clone(), true
}

// Relation returns a copy of the relation by from/to/kind/id.
func (g *EntityGraph) Relation(id, from, to, kind string) (EntityRelation, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	key := relationKey(id, from, to, kind)
	r, ok := g.relations[key]
	if !ok {
		return EntityRelation{}, false
	}
	return r.clone(), true
}

// Entities returns all entities as a deterministic slice (sorted by ID).
func (g *EntityGraph) Entities() []Entity {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ids := make([]string, 0, len(g.entities))
	for id := range g.entities {
		ids = append(ids, id)
	}
	sortStrings(ids)
	out := make([]Entity, 0, len(ids))
	for _, id := range ids {
		out = append(out, g.entities[id].clone())
	}
	return out
}

// Relations returns all relations as a deterministic slice (sorted by key).
func (g *EntityGraph) Relations() []EntityRelation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	keys := make([]string, 0, len(g.relations))
	for k := range g.relations {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]EntityRelation, 0, len(keys))
	for _, k := range keys {
		out = append(out, g.relations[k].clone())
	}
	return out
}

// EntitiesByKind returns entities of a specific kind, sorted by ID.
func (g *EntityGraph) EntitiesByKind(kind EntityKind) []Entity {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ids := g.byKind[kind]
	if len(ids) == 0 {
		return nil
	}
	ids = append([]string(nil), ids...)
	sortStrings(ids)
	out := make([]Entity, 0, len(ids))
	for _, id := range ids {
		out = append(out, g.entities[id].clone())
	}
	return out
}

// RelationsByEvidenceClass returns relations filtered by evidence class, sorted by key.
func (g *EntityGraph) RelationsByEvidenceClass(ec EvidenceClass) []EntityRelation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var keys []string
	for k, r := range g.relations {
		if r.EvidenceClass == ec {
			keys = append(keys, k)
		}
	}
	sortStrings(keys)
	out := make([]EntityRelation, 0, len(keys))
	for _, k := range keys {
		out = append(out, g.relations[k].clone())
	}
	return out
}

// Neighbors returns the neighboring entities for a given entity ID.
// Includes both incoming and outgoing neighbors. Returns deterministic slice.
func (g *EntityGraph) Neighbors(id string) []Entity {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if _, ok := g.entities[id]; !ok {
		return nil
	}
	neighborSet := make(map[string]struct{})
	for _, k := range g.byFrom[id] {
		r := g.relations[k]
		neighborSet[r.To] = struct{}{}
	}
	for _, k := range g.byTo[id] {
		r := g.relations[k]
		neighborSet[r.From] = struct{}{}
	}
	var neighbors []string
	for n := range neighborSet {
		neighbors = append(neighbors, n)
	}
	sortStrings(neighbors)
	out := make([]Entity, 0, len(neighbors))
	for _, n := range neighbors {
		out = append(out, g.entities[n].clone())
	}
	return out
}

// Outgoing returns outgoing relations for an entity, sorted by key.
func (g *EntityGraph) Outgoing(id string) []EntityRelation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	keys := g.byFrom[id]
	if len(keys) == 0 {
		return nil
	}
	keys = append([]string(nil), keys...)
	sortStrings(keys)
	out := make([]EntityRelation, 0, len(keys))
	for _, k := range keys {
		out = append(out, g.relations[k].clone())
	}
	return out
}

// Incoming returns incoming relations for an entity, sorted by key.
func (g *EntityGraph) Incoming(id string) []EntityRelation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	keys := g.byTo[id]
	if len(keys) == 0 {
		return nil
	}
	keys = append([]string(nil), keys...)
	sortStrings(keys)
	out := make([]EntityRelation, 0, len(keys))
	for _, k := range keys {
		out = append(out, g.relations[k].clone())
	}
	return out
}

// EntityCount returns the number of entities in the graph.
func (g *EntityGraph) EntityCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.entities)
}

// RelationCount returns the number of relations in the graph.
func (g *EntityGraph) RelationCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.relations)
}

// MaxEntities returns the configured entity limit.
func (g *EntityGraph) MaxEntities() int { return g.maxEntities }

// MaxRelations returns the configured relation limit.
func (g *EntityGraph) MaxRelations() int { return g.maxRelations }

// relationKey creates a deterministic key for a relation.
// Includes ID as final tiebreaker so two relations with same from/to/kind
// but different IDs get distinct keys and stable ordering.
func relationKey(id, from, to, kind string) string {
	return from + "\x00" + to + "\x00" + kind + "\x00" + id
}

// entitiesEqual reports whether two entities have identical content.
func entitiesEqual(a, b Entity) bool {
	if a.ID != b.ID || a.Kind != b.Kind || a.Label != b.Label || a.Value != b.Value {
		return false
	}
	if len(a.Attributes) != len(b.Attributes) {
		return false
	}
	for k, v := range a.Attributes {
		if b.Attributes[k] != v {
			return false
		}
	}
	return true
}

// relationsEqual reports whether two relations have identical content.
func relationsEqual(a, b EntityRelation) bool {
	return a.ID == b.ID &&
		a.From == b.From &&
		a.To == b.To &&
		a.Kind == b.Kind &&
		a.Directed == b.Directed &&
		a.EvidenceClass == b.EvidenceClass &&
		a.ProvenanceRef == b.ProvenanceRef &&
		a.Label == b.Label
}

// sortStrings sorts a string slice in place.
func sortStrings(s []string) {
	for i := 0; i < len(s)-1; i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
