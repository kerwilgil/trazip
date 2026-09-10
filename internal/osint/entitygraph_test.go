// Package osint tests for the entity graph model.
package osint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntityGraph_Empty(t *testing.T) {
	g := NewEntityGraph()
	require.Equal(t, 0, g.EntityCount())
	require.Equal(t, 0, g.RelationCount())
	require.Equal(t, DefaultMaxEntities, g.MaxEntities())
	require.Equal(t, DefaultMaxRelations, g.MaxRelations())
	require.Len(t, g.Entities(), 0)
	require.Len(t, g.Relations(), 0)
}

func TestEntityGraph_AddEntity(t *testing.T) {
	g := NewEntityGraph()
	e := Entity{
		ID:    "e1",
		Kind:  EntityKindIP,
		Label: "IP Address",
		Value: "1.1.1.1",
	}
	require.NoError(t, g.AddEntity(e))
	require.Equal(t, 1, g.EntityCount())

	got, ok := g.Entity("e1")
	require.True(t, ok)
	require.Equal(t, e.ID, got.ID)
	require.Equal(t, e.Kind, got.Kind)
	require.Equal(t, e.Label, got.Label)
	require.Equal(t, e.Value, got.Value)
}

func TestEntityGraph_AddEntity_Validates(t *testing.T) {
	g := NewEntityGraph()
	tests := []struct {
		name  string
		e     Entity
		want  string
	}{
		{"missing ID", Entity{Kind: EntityKindIP, Label: "L", Value: "V"}, "missing ID"},
		{"missing kind", Entity{ID: "e1", Label: "L", Value: "V"}, "missing kind"},
		{"missing label", Entity{ID: "e1", Kind: EntityKindIP, Value: "V"}, "missing label"},
		{"missing value", Entity{ID: "e1", Kind: EntityKindIP, Label: "L"}, "missing value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := g.AddEntity(tc.e)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestEntityGraph_AddEntity_IdempotentIfIdentical(t *testing.T) {
	g := NewEntityGraph()
	e := Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1"}
	require.NoError(t, g.AddEntity(e))
	require.NoError(t, g.AddEntity(e)) // second add identical = no-op
	require.Equal(t, 1, g.EntityCount())
}

func TestEntityGraph_AddEntity_RejectsConflicting(t *testing.T) {
	g := NewEntityGraph()
	e1 := Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1"}
	e2 := Entity{ID: "e1", Kind: EntityKindDomain, Label: "Domain", Value: "example.com"}
	require.NoError(t, g.AddEntity(e1))
	err := g.AddEntity(e2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "different content")
	require.Equal(t, 1, g.EntityCount())
}

func TestEntityGraph_AddRelation(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindDomain, Label: "Domain", Value: "example.com"}))

	r := EntityRelation{
		ID:            "r1",
		From:          "e1",
		To:            "e2",
		Kind:          "resolves_to",
		Directed:      true,
		EvidenceClass: EvidenceObserved,
		ProvenanceRef: "prov-1",
		Label:         "Resolves",
	}
	require.NoError(t, g.AddRelation(r))
	require.Equal(t, 1, g.RelationCount())

	got, ok := g.Relation("r1", "e1", "e2", "resolves_to")
	require.True(t, ok)
	require.Equal(t, r.ID, got.ID)
	require.Equal(t, r.From, got.From)
	require.Equal(t, r.To, got.To)
	require.Equal(t, r.Kind, got.Kind)
	require.Equal(t, r.Directed, got.Directed)
	require.Equal(t, r.EvidenceClass, got.EvidenceClass)
	require.Equal(t, r.ProvenanceRef, got.ProvenanceRef)
	require.Equal(t, r.Label, got.Label)
}

func TestEntityGraph_AddRelation_Validates(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindDomain, Label: "Domain", Value: "example.com"}))

	tests := []struct {
		name string
		r    EntityRelation
		want string
	}{
		{"missing ID", EntityRelation{From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov"}, "missing ID"},
		{"missing from", EntityRelation{ID: "r1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov"}, "missing from"},
		{"missing to", EntityRelation{ID: "r1", From: "e1", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov"}, "missing to"},
		{"missing kind", EntityRelation{ID: "r1", From: "e1", To: "e2", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov"}, "missing kind"},
		{"invalid evidence class", EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceUnknown}, "invalid evidence class"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := g.AddRelation(tc.r)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestEntityGraph_AddRelation_MissingFrom(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindDomain, Label: "Domain", Value: "example.com"}))
	r := EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov"}
	err := g.AddRelation(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "from entity")
}

func TestEntityGraph_AddRelation_MissingTo(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1"}))
	r := EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov"}
	err := g.AddRelation(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "to entity")
}

func TestEntityGraph_AddRelation_DuplicateRejected(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindDomain, Label: "Domain", Value: "example.com"}))
	r := EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov"}
	require.NoError(t, g.AddRelation(r))
	err := g.AddRelation(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestEntityGraph_DeterministicOrdering(t *testing.T) {
	g := NewEntityGraph()
	// Add in random order
	require.NoError(t, g.AddEntity(Entity{ID: "e3", Kind: EntityKindIP, Label: "IP3", Value: "3.3.3.3"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))

	entities := g.Entities()
	require.Len(t, entities, 3)
	require.Equal(t, "e1", entities[0].ID)
	require.Equal(t, "e2", entities[1].ID)
	require.Equal(t, "e3", entities[2].ID)

	require.NoError(t, g.AddRelation(EntityRelation{ID: "r3", From: "e3", To: "e1", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3"}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1"}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r2", From: "e2", To: "e3", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2"}))

	relations := g.Relations()
	require.Len(t, relations, 3)
	// Keys are sorted: e1->e2 (r1), e2->e3 (r2), e3->e1 (r3)
	require.Equal(t, "e1", relations[0].From)
	require.Equal(t, "e2", relations[0].To)
	require.Equal(t, "r1", relations[0].ID)
	require.Equal(t, "e2", relations[1].From)
	require.Equal(t, "e3", relations[1].To)
	require.Equal(t, "r2", relations[1].ID)
	require.Equal(t, "e3", relations[2].From)
	require.Equal(t, "e1", relations[2].To)
	require.Equal(t, "r3", relations[2].ID)
}

func TestEntityGraph_EntitiesByKind(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindDomain, Label: "Domain", Value: "example.com"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e3", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))

	ips := g.EntitiesByKind(EntityKindIP)
	require.Len(t, ips, 2)
	require.Equal(t, "e1", ips[0].ID)
	require.Equal(t, "e3", ips[1].ID)

	domains := g.EntitiesByKind(EntityKindDomain)
	require.Len(t, domains, 1)
	require.Equal(t, "e2", domains[0].ID)

	empty := g.EntitiesByKind(EntityKindASN)
	require.Nil(t, empty)
}

func TestEntityGraph_RelationsByEvidenceClass(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e3", Kind: EntityKindIP, Label: "IP3", Value: "3.3.3.3"}))

	require.NoError(t, g.AddRelation(EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1"}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r2", From: "e2", To: "e3", Kind: "k", EvidenceClass: EvidencePossibleContext}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r3", From: "e3", To: "e1", Kind: "k", EvidenceClass: EvidenceNotProven}))

	observed := g.RelationsByEvidenceClass(EvidenceObserved)
	require.Len(t, observed, 1)
	require.Equal(t, "e1", observed[0].From)

	possible := g.RelationsByEvidenceClass(EvidencePossibleContext)
	require.Len(t, possible, 1)
	require.Equal(t, "e2", possible[0].From)

	notProven := g.RelationsByEvidenceClass(EvidenceNotProven)
	require.Len(t, notProven, 1)
	require.Equal(t, "e3", notProven[0].From)
}

func TestEntityGraph_Neighbors(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e3", Kind: EntityKindIP, Label: "IP3", Value: "3.3.3.3"}))

	require.NoError(t, g.AddRelation(EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", Directed: true, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1"}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r2", From: "e3", To: "e1", Kind: "k", Directed: true, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2"}))

	neighbors := g.Neighbors("e1")
	require.Len(t, neighbors, 2)
	require.Equal(t, "e2", neighbors[0].ID)
	require.Equal(t, "e3", neighbors[1].ID)

	// Non-existent
	require.Nil(t, g.Neighbors("nonexistent"))
}

func TestEntityGraph_OutgoingIncoming(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e3", Kind: EntityKindIP, Label: "IP3", Value: "3.3.3.3"}))

	require.NoError(t, g.AddRelation(EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", Directed: true, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1"}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r2", From: "e3", To: "e1", Kind: "k", Directed: true, EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2"}))

	out := g.Outgoing("e1")
	require.Len(t, out, 1)
	require.Equal(t, "e1", out[0].From)
	require.Equal(t, "e2", out[0].To)

	in := g.Incoming("e1")
	require.Len(t, in, 1)
	require.Equal(t, "e3", in[0].From)
	require.Equal(t, "e1", in[0].To)
}

func TestEntityGraph_EntityBoundEnforced(t *testing.T) {
	g := NewEntityGraphWithBounds(2, DefaultMaxRelations)
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))
	err := g.AddEntity(Entity{ID: "e3", Kind: EntityKindIP, Label: "IP3", Value: "3.3.3.3"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "entity limit reached")
	require.Equal(t, 2, g.EntityCount())
}

func TestEntityGraph_RelationBoundEnforced(t *testing.T) {
	g := NewEntityGraphWithBounds(DefaultMaxEntities, 2)
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e3", Kind: EntityKindIP, Label: "IP3", Value: "3.3.3.3"}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov1"}))
	require.NoError(t, g.AddRelation(EntityRelation{ID: "r2", From: "e2", To: "e3", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov2"}))
	err := g.AddRelation(EntityRelation{ID: "r3", From: "e3", To: "e1", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov3"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "relation limit reached")
	require.Equal(t, 2, g.RelationCount())
}

func TestEntityGraph_NoMutationThroughRetainedSlices(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1", Attributes: map[string]string{"a": "1"}}))

	e1 := g.Entities()[0]
	e1.Attributes["a"] = "mutated"

	e2 := g.Entities()[0]
	require.Equal(t, "1", e2.Attributes["a"], "original entity should not be mutated")
}

func TestEntityGraph_EvidenceClassBehavior(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP1", Value: "1.1.1.1"}))
	require.NoError(t, g.AddEntity(Entity{ID: "e2", Kind: EntityKindIP, Label: "IP2", Value: "2.2.2.2"}))

	// OBSERVED requires provenance ref
	r1 := EntityRelation{ID: "r1", From: "e1", To: "e2", Kind: "k", EvidenceClass: EvidenceObserved, ProvenanceRef: "prov-1"}
	require.NoError(t, g.AddRelation(r1))

	// POSSIBLE_CONTEXT does not require provenance ref
	r2 := EntityRelation{ID: "r2", From: "e1", To: "e2", Kind: "k2", EvidenceClass: EvidencePossibleContext}
	require.NoError(t, g.AddRelation(r2))

	// NOT_PROVEN does not require provenance ref
	r3 := EntityRelation{ID: "r3", From: "e1", To: "e2", Kind: "k3", EvidenceClass: EvidenceNotProven}
	require.NoError(t, g.AddRelation(r3))

	// Verify they remain distinct - no auto-promotion
	observed := g.RelationsByEvidenceClass(EvidenceObserved)
	require.Len(t, observed, 1)
	require.Equal(t, EvidenceObserved, observed[0].EvidenceClass)

	possible := g.RelationsByEvidenceClass(EvidencePossibleContext)
	require.Len(t, possible, 1)
	require.Equal(t, EvidencePossibleContext, possible[0].EvidenceClass)

	notProven := g.RelationsByEvidenceClass(EvidenceNotProven)
	require.Len(t, notProven, 1)
	require.Equal(t, EvidenceNotProven, notProven[0].EvidenceClass)
}

func TestEntityGraph_SelfEdgeAllowed(t *testing.T) {
	g := NewEntityGraph()
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1"}))
	r := EntityRelation{ID: "r1", From: "e1", To: "e1", Kind: "self_ref", Directed: true, EvidenceClass: EvidenceNotProven}
	require.NoError(t, g.AddRelation(r)) // Self-edge allowed if explicitly added
	require.Equal(t, 1, g.RelationCount())
}

func TestEntityGraph_AttributesDeepCopy(t *testing.T) {
	g := NewEntityGraph()
	attrs := map[string]string{"a": "1"}
	require.NoError(t, g.AddEntity(Entity{ID: "e1", Kind: EntityKindIP, Label: "IP", Value: "1.1.1.1", Attributes: attrs}))

	// Mutate original map
	attrs["a"] = "mutated"

	e := g.Entities()[0]
	require.Equal(t, "1", e.Attributes["a"], "entity attributes should be deep copied")
}