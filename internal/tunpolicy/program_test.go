package tunpolicy

import (
	"strings"
	"testing"
)

func TestProgramDigestIgnoresOnlyRuntimeData(t *testing.T) {
	t.Parallel()
	original := `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"lanrith","handle":1}},{"set":{"family":"inet","table":"lanrith","name":"tp_bound4","handle":2,"type":["ifname","ether_addr","ipv4_addr"],"flags":["timeout"]}},{"set":{"family":"inet","table":"lanrith","name":"owner_targets","type":"ipv4_addr","elem":["10.0.0.1"]}},{"rule":{"family":"inet","table":"lanrith","chain":"forward","handle":3,"expr":[{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}]}`
	digest, err := ProgramDigest([]byte(original))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, input string
		same        bool
	}{
		{"kernel handles", strings.ReplaceAll(original, `"handle":1`, `"handle":18`), true},
		{"counter observations", strings.ReplaceAll(original, `"packets":0,"bytes":0`, `"packets":25,"bytes":3000`), true},
		{"current binding data", strings.ReplaceAll(original, `"flags":["timeout"]`, `"flags":["timeout"],"elem":[{"concat":["lan","02:00:00:00:00:02","10.0.0.2"]}]`), true},
		{"static destination changed", strings.ReplaceAll(original, "10.0.0.1", "10.0.0.2"), false},
		{"rule verdict changed", strings.ReplaceAll(original, `"drop":null`, `"accept":null`), false},
		{"binding schema changed", strings.ReplaceAll(original, `"ifname","ether_addr","ipv4_addr"`, `"ipv4_addr"`), false},
		{"binding moved to another table", strings.ReplaceAll(original, `"table":"lanrith","name":"tp_bound4"`, `"table":"other","name":"tp_bound4"`), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := ProgramDigest([]byte(test.input))
			if err != nil || (got == digest) != test.same {
				t.Fatalf("digest equal=%v want %v: %v", got == digest, test.same, err)
			}
		})
	}
}

func TestProgramDigestStillValidatesDiscardedMutableData(t *testing.T) {
	t.Parallel()
	prefix := `{"nftables":[{"set":{"family":"inet","table":"lanrith","name":"tp_bound4","type":"ipv4_addr","elem":`
	for _, invalid := range []string{
		`[{"x":1,"x":2}]`,
		`[{"x":1,"\u0078":2}]`,
		strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40),
	} {
		if _, err := ProgramDigest([]byte(prefix + invalid + `}}]}`)); err == nil {
			t.Fatal("discarded mutable data bypassed structural validation")
		}
	}
}

func TestProgramDigestPreservesWideStaticNumbers(t *testing.T) {
	t.Parallel()
	input := `{"nftables":[{"map":{"family":"inet","table":"lanrith","name":"static","elem":[9007199254740992]}}]}`
	first, err := ProgramDigest([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProgramDigest([]byte(strings.ReplaceAll(input, "9007199254740992", "9007199254740993")))
	if err != nil || first == second {
		t.Fatal("static numbers lost precision", err)
	}
}
