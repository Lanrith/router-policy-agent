package strictjson_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

func BenchmarkStrictNFTEnvelope(b *testing.B) {
	row := `{"rule":{"family":"inet","table":"router_policy","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lan10"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":{"prefix":{"addr":"fdca:1a2b:3::","len":64}}}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[80,443]}}},{"drop":null}]}}`
	data := []byte(`{"nftables":[` + strings.Repeat(row+",", 4095) + row + `]}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		var envelope map[string]json.RawMessage
		if err := strictjson.Decode(data, &envelope, len(data)); err != nil {
			b.Fatal(err)
		}
	}
}
