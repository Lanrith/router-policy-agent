package firewall

import (
	"bytes"
	"testing"
)

func TestFixedLiteralSetComparisonKeepsEveryTupleAndOrderedExpression(t *testing.T) {
	t.Parallel()
	original := []byte(`[{"match":{"left":{"meta":{"key":"mark"}},"right":{"set":[{"concat":[6,"lan13","fdca:1a2b:3::10","tcp"]},{"concat":[18,"lan13","fdca:1a2b:3::11","tcp"]}]}}},{"goto":{"target":"checked"}}]`)
	reordered := []byte(`[{"match":{"left":{"meta":{"key":"mark"}},"right":{"set":[{"concat":[18,"lan13","fdca:1a2b:3::11","tcp"]},{"concat":[6,"lan13","fdca:1a2b:3::10","tcp"]}]}}},{"goto":{"target":"checked"}}]`)
	before, err := canonicalFixedGuardJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	after, err := canonicalFixedGuardJSON(reordered)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unordered literal set changed meaning", err)
	}
	for _, changed := range [][]byte{
		bytes.Replace(original, []byte(`6,"lan13"`), []byte(`6,"lan10"`), 1),
		bytes.Replace(original, []byte(`18,"lan13"`), []byte(`18,"tcp"`), 1),
		bytes.Replace(original, []byte(`fdca:1a2b:3::10`), []byte(`fdca:1a2b:3::11`), 1),
		[]byte(`[{"goto":{"target":"checked"}},{"match":{"left":{"meta":{"key":"mark"}},"right":{"set":[{"concat":[6,"lan13","fdca:1a2b:3::10","tcp"]},{"concat":[18,"lan13","fdca:1a2b:3::11","tcp"]}]}}}]`),
	} {
		value, err := canonicalFixedGuardJSON(changed)
		if err == nil && bytes.Equal(value, before) {
			t.Fatal("normalization lost an interface, identity, address or expression order")
		}
	}
	batchBefore, err := canonicalGuardJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	batchAfter, err := canonicalGuardJSON(reordered)
	if err != nil || bytes.Equal(batchBefore, batchAfter) {
		t.Fatal("fixed-expression normalization changed the runtime batch boundary", err)
	}
}
