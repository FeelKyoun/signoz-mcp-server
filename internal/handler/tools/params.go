package tools

import (
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// extractArgs safely extracts the arguments map from a CallToolRequest.
func extractArgs(req mcp.CallToolRequest) (map[string]any, error) {
	args, ok := req.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments payload")
	}
	return args, nil
}

// requireString extracts a required non-empty string parameter from args.
func requireString(args map[string]any, key string) (string, error) {
	val, ok := args[key].(string)
	if !ok || val == "" {
		return "", fmt.Errorf("%s is required and must be a non-empty string", key)
	}
	return val, nil
}

// optionalString extracts an optional string parameter, returning defaultVal if absent or empty.
func optionalString(args map[string]any, key string, defaultVal string) string {
	if val, ok := args[key].(string); ok && val != "" {
		return val
	}
	return defaultVal
}

// extractAndMarshalObject extracts a nested object by key and marshals it to JSON bytes.
func extractAndMarshalObject(args map[string]any, key string) ([]byte, error) {
	obj, ok := args[key].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s parameter must be a JSON object", key)
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s: %w", key, err)
	}
	return data, nil
}
