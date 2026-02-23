package types

import (
	"encoding/json"
	"testing"
)

// TestFilterExpressionRoundtrip verifies that expression-style filters survive JSON roundtrip
func TestFilterExpressionRoundtrip(t *testing.T) {
	original := `{"schemaVersion":"v1","start":1700000000000,"end":1700003600000,"requestType":"raw","compositeQuery":{"queries":[{"type":"builder_query","spec":{"name":"A","signal":"traces","disabled":false,"filter":{"expression":"service.name = 'frontend'"},"limit":10,"offset":0,"order":[],"having":{"expression":""},"selectFields":[]}}]},"formatOptions":{"formatTableResultForUI":false,"fillGaps":false},"variables":{}}`

	var payload QueryPayload
	if err := json.Unmarshal([]byte(original), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Check filter is preserved
	filter := payload.CompositeQuery.Queries[0].Spec.Filter
	if filter == nil {
		t.Fatal("filter is nil after unmarshal")
	}

	var filterMap map[string]any
	if err := json.Unmarshal(filter, &filterMap); err != nil {
		t.Fatalf("failed to parse filter: %v", err)
	}

	expr, ok := filterMap["expression"].(string)
	if !ok || expr != "service.name = 'frontend'" {
		t.Errorf("expected expression 'service.name = 'frontend'', got %v", filterMap["expression"])
	}

	// Re-marshal and verify
	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundtripped QueryPayload
	if err := json.Unmarshal(out, &roundtripped); err != nil {
		t.Fatalf("second unmarshal failed: %v", err)
	}

	var rtFilter map[string]any
	if err := json.Unmarshal(roundtripped.CompositeQuery.Queries[0].Spec.Filter, &rtFilter); err != nil {
		t.Fatalf("failed to parse roundtripped filter: %v", err)
	}

	if rtFilter["expression"] != "service.name = 'frontend'" {
		t.Errorf("filter expression lost after roundtrip: %v", rtFilter)
	}
}

// TestFilterItemsRoundtrip verifies that items-style filters (the ones LLMs tend to send) survive JSON roundtrip
func TestFilterItemsRoundtrip(t *testing.T) {
	original := `{"schemaVersion":"v1","start":1700000000000,"end":1700003600000,"requestType":"raw","compositeQuery":{"queries":[{"type":"builder_query","spec":{"name":"A","signal":"traces","disabled":false,"filter":{"items":[{"key":{"key":"service.name","dataType":"string","type":"resource","isColumn":false},"op":"=","value":"frontend"}],"op":"AND"},"limit":10,"offset":0,"order":[],"having":{"expression":""},"selectFields":[]}}]},"formatOptions":{"formatTableResultForUI":false,"fillGaps":false},"variables":{}}`

	var payload QueryPayload
	if err := json.Unmarshal([]byte(original), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	filter := payload.CompositeQuery.Queries[0].Spec.Filter
	if filter == nil {
		t.Fatal("filter is nil after unmarshal")
	}

	var filterMap map[string]any
	if err := json.Unmarshal(filter, &filterMap); err != nil {
		t.Fatalf("failed to parse filter: %v", err)
	}

	// Verify items array is preserved
	items, ok := filterMap["items"].([]any)
	if !ok {
		t.Fatalf("items field missing or wrong type: %v", filterMap)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	// Verify op field is preserved
	op, ok := filterMap["op"].(string)
	if !ok || op != "AND" {
		t.Errorf("expected op 'AND', got %v", filterMap["op"])
	}

	// Verify item details
	item := items[0].(map[string]any)
	key := item["key"].(map[string]any)
	if key["key"] != "service.name" {
		t.Errorf("expected key 'service.name', got %v", key["key"])
	}
	if item["op"] != "=" {
		t.Errorf("expected op '=', got %v", item["op"])
	}
	if item["value"] != "frontend" {
		t.Errorf("expected value 'frontend', got %v", item["value"])
	}

	// Re-marshal and verify roundtrip
	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundtripped QueryPayload
	if err := json.Unmarshal(out, &roundtripped); err != nil {
		t.Fatalf("second unmarshal failed: %v", err)
	}

	var rtFilter map[string]any
	if err := json.Unmarshal(roundtripped.CompositeQuery.Queries[0].Spec.Filter, &rtFilter); err != nil {
		t.Fatalf("failed to parse roundtripped filter: %v", err)
	}

	rtItems, ok := rtFilter["items"].([]any)
	if !ok || len(rtItems) != 1 {
		t.Errorf("items lost after roundtrip: %v", rtFilter)
	}
	if rtFilter["op"] != "AND" {
		t.Errorf("op lost after roundtrip: %v", rtFilter)
	}
}

// TestBuildFilterJSON verifies the helper function
func TestBuildFilterJSON(t *testing.T) {
	result := BuildFilterJSON("service.name = 'frontend'")

	var filterMap map[string]string
	if err := json.Unmarshal(result, &filterMap); err != nil {
		t.Fatalf("failed to unmarshal BuildFilterJSON result: %v", err)
	}

	if filterMap["expression"] != "service.name = 'frontend'" {
		t.Errorf("expected expression \"service.name = 'frontend'\", got %q", filterMap["expression"])
	}
}

// TestFilterOmittedWhenEmpty verifies that empty/nil filter is omitted in JSON
func TestFilterOmittedWhenEmpty(t *testing.T) {
	spec := QuerySpec{
		Name:   "A",
		Signal: "traces",
	}

	out, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if _, exists := m["filter"]; exists {
		t.Error("filter should be omitted when nil/empty")
	}
}
