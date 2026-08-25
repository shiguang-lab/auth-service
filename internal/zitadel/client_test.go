package zitadel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSearchUsersUsesSchemaSpecificQueryBodies(t *testing.T) {
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		bodies = append(bodies, body)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"result":[]}`))
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{baseURL: server.URL, host: parsed.Host, pat: "test-pat", http: server.Client()}

	if _, err := client.SearchUsers(context.Background(), "alice", 5); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("request count = %d, want 2", len(bodies))
	}
	assertTextQuery(t, bodies[0], "loginNameQuery", "loginName", "displayName")
	assertTextQuery(t, bodies[1], "displayNameQuery", "displayName", "loginName")
}

func assertTextQuery(t *testing.T, body map[string]any, queryName, valueName, forbiddenName string) {
	t.Helper()
	queries, ok := body["queries"].([]any)
	if !ok || len(queries) != 1 {
		t.Fatalf("queries = %#v", body["queries"])
	}
	query, ok := queries[0].(map[string]any)
	if !ok || len(query) != 1 {
		t.Fatalf("query = %#v", queries[0])
	}
	value, ok := query[queryName].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v", queryName, query[queryName])
	}
	if value[valueName] != "alice" || value["method"] != "TEXT_QUERY_METHOD_CONTAINS_IGNORE_CASE" {
		t.Fatalf("query value = %#v", value)
	}
	if _, exists := value[forbiddenName]; exists {
		t.Fatalf("query contains forbidden field %q: %#v", forbiddenName, value)
	}
}
