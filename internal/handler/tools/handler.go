package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"

	signozclient "github.com/SigNoz/signoz-mcp-server/internal/client"
	"github.com/SigNoz/signoz-mcp-server/pkg/dashboard"
	"github.com/SigNoz/signoz-mcp-server/pkg/paginate"
	"github.com/SigNoz/signoz-mcp-server/pkg/timeutil"
	"github.com/SigNoz/signoz-mcp-server/pkg/types"
	"github.com/SigNoz/signoz-mcp-server/pkg/util"
)

type Handler struct {
	client      *signozclient.SigNoz
	logger      *zap.Logger
	signozURL   string
	clientCache map[string]*signozclient.SigNoz
	cacheMutex  sync.RWMutex
}

func NewHandler(log *zap.Logger, client *signozclient.SigNoz, signozURL string) *Handler {
	return &Handler{
		client:      client,
		logger:      log,
		signozURL:   signozURL,
		clientCache: make(map[string]*signozclient.SigNoz),
	}
}

// getClient returns the appropriate client based on the context
// If an API key is found in the context, it returns a cached client with that key
// Otherwise, it returns the default client
func (h *Handler) GetClient(ctx context.Context) *signozclient.SigNoz {
	if apiKey, ok := util.GetAPIKey(ctx); ok && apiKey != "" && h.signozURL != "" {
		// Check cache first
		h.cacheMutex.RLock()
		if cachedClient, exists := h.clientCache[apiKey]; exists {
			h.cacheMutex.RUnlock()
			return cachedClient
		}
		h.cacheMutex.RUnlock()

		h.cacheMutex.Lock()
		defer h.cacheMutex.Unlock()

		// just to check if other goroutine created client
		if cachedClient, exists := h.clientCache[apiKey]; exists {
			return cachedClient
		}

		h.logger.Debug("Creating client with API key from context")
		newClient := signozclient.NewClient(h.logger, h.signozURL, apiKey)
		h.clientCache[apiKey] = newClient
		return newClient
	}
	return h.client
}

func (h *Handler) RegisterMetricsHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering metrics handlers")

	listKeysTool := mcp.NewTool("signoz_list_metric_keys",
		mcp.WithDescription("List available metric keys from SigNoz. IMPORTANT: This tool supports pagination using 'limit' and 'offset' parameters. Use limit to control the number of results returned (default: 50). Use offset to skip results for pagination (default: 0). For large result sets, paginate by incrementing offset: offset=0 for first page, offset=50 for second page (if limit=50), offset=100 for third page, etc."),
		mcp.WithString("limit", mcp.Description("Maximum number of keys to return per page. Use this to paginate through large result sets. Default: 50. Example: '50' for 50 results, '100' for 100 results. Must be greater than 0.")),
		mcp.WithString("offset", mcp.Description("Number of results to skip before returning results. Use for pagination: offset=0 for first page, offset=50 for second page (if limit=50), offset=100 for third page, etc. Default: 0. Must be >= 0.")),
	)

	s.AddTool(listKeysTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_metric_keys")
		limit, offset := paginate.ParseParams(req.Params.Arguments)

		client := h.GetClient(ctx)
		resp, err := client.ListMetricKeys(ctx)
		if err != nil {
			h.logger.Error("Failed to list metric keys", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		// received api data - {"data": {"attributeKeys": [...]}}
		var response map[string]any
		if err := json.Unmarshal(resp, &response); err != nil {
			h.logger.Error("Failed to parse metric keys response", zap.Error(err))
			return mcp.NewToolResultError("failed to parse response: " + err.Error()), nil
		}

		dataObj, ok := response["data"].(map[string]any)
		if !ok {
			h.logger.Error("Invalid metric keys response format", zap.Any("data", response["data"]))
			return mcp.NewToolResultError("invalid response format: expected data object"), nil
		}

		attributeKeys, ok := dataObj["attributeKeys"].([]any)
		if !ok {
			h.logger.Error("Invalid attributeKeys format", zap.Any("attributeKeys", dataObj["attributeKeys"]))
			return mcp.NewToolResultError("invalid response format: expected attributeKeys array"), nil
		}

		total := len(attributeKeys)
		pagedKeys := paginate.Array(attributeKeys, offset, limit)

		// response wrapped in paged structured format
		resultJSON, err := paginate.Wrap(pagedKeys, total, offset, limit)
		if err != nil {
			h.logger.Error("Failed to wrap metric keys with pagination", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal response: " + err.Error()), nil
		}

		return mcp.NewToolResultText(string(resultJSON)), nil
	})

	searchKeysTool := mcp.NewTool("signoz_search_metric_by_text",
		mcp.WithDescription("Search metrics by text (substring autocomplete)"),
		mcp.WithString("searchText", mcp.Required(), mcp.Description("Search text for metric keys")),
	)

	s.AddTool(searchKeysTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		searchText, ok := req.Params.Arguments.(map[string]any)["searchText"].(string)
		if !ok {
			h.logger.Warn("Invalid searchText parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "searchText" must be a string. Example: {"searchText": "cpu_usage"}`), nil
		}
		if searchText == "" {
			h.logger.Warn("Empty searchText parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "searchText" cannot be empty. Provide a search term like "cpu", "memory", or "request"`), nil
		}

		h.logger.Debug("Tool called: signoz_search_metric_by_text", zap.String("searchText", searchText))
		client := h.GetClient(ctx)
		resp, err := client.SearchMetricByText(ctx, searchText)
		if err != nil {
			h.logger.Error("Failed to search metric by text", zap.String("searchText", searchText), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(resp)), nil
	})

	getMetricsAvailableFieldsTool := mcp.NewTool("signoz_get_metrics_available_fields",
		mcp.WithDescription("Get available field names for metric queries"),
		mcp.WithString("searchText", mcp.Description("Search text to filter available fields (optional)")),
	)

	s.AddTool(getMetricsAvailableFieldsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		searchText := ""
		if search, ok := args["searchText"].(string); ok && search != "" {
			searchText = search
		}

		h.logger.Debug("Tool called: signoz_get_metrics_available_fields", zap.String("searchText", searchText))
		client := h.GetClient(ctx)
		result, err := client.GetMetricsAvailableFields(ctx, searchText)
		if err != nil {
			h.logger.Error("Failed to get metrics available fields", zap.String("searchText", searchText), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getMetricsFieldValuesTool := mcp.NewTool("signoz_get_metrics_field_values",
		mcp.WithDescription("Get available field values for metric queries"),
		mcp.WithString("fieldName", mcp.Required(), mcp.Description("Field name to get values for (e.g., metric name)")),
		mcp.WithString("searchText", mcp.Description("Search text to filter values (optional)")),
	)

	s.AddTool(getMetricsFieldValuesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Error("Invalid arguments type", zap.Any("arguments", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: invalid arguments format. Expected object with "fieldName" string.`), nil
		}

		fieldName, ok := args["fieldName"].(string)
		if !ok || fieldName == "" {
			h.logger.Warn("Missing or invalid fieldName", zap.Any("args", args), zap.Any("fieldName", args["fieldName"]))
			return mcp.NewToolResultError(`Parameter validation failed: "fieldName" must be a non-empty string. Examples: {"fieldName": "aws_ApplicationELB_ConsumedLCUs_max"}, {"fieldName": "cpu_usage"}`), nil
		}

		searchText := ""
		if search, ok := args["searchText"].(string); ok && search != "" {
			searchText = search
		}

		h.logger.Debug("Tool called: signoz_get_metrics_field_values", zap.String("fieldName", fieldName), zap.String("searchText", searchText))
		client := h.GetClient(ctx)
		result, err := client.GetMetricsFieldValues(ctx, fieldName, searchText)
		if err != nil {
			h.logger.Error("Failed to get metrics field values", zap.String("fieldName", fieldName), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterAlertsHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering alerts handlers")

	alertsTool := mcp.NewTool("signoz_list_alerts",
		mcp.WithDescription("List active alerts from SigNoz. Returns list of alert with: alert name, rule ID, severity, start time, end time, and state. IMPORTANT: This tool supports pagination using 'limit' and 'offset' parameters. The response includes 'pagination' metadata with 'total', 'hasMore', and 'nextOffset' fields. When searching for a specific alert, ALWAYS check 'pagination.hasMore' - if true, continue paginating through all pages using 'nextOffset' until you find the item or 'hasMore' is false. Never conclude an item doesn't exist until you've checked all pages. Default: limit=50, offset=0."),
		mcp.WithString("limit", mcp.Description("Maximum number of alerts to return per page. Use this to paginate through large result sets. Default: 50. Example: '50' for 50 results, '100' for 100 results. Must be greater than 0.")),
		mcp.WithString("offset", mcp.Description("Number of results to skip before returning results. Use for pagination: offset=0 for first page, offset=50 for second page (if limit=50), offset=100 for third page, etc. Check 'pagination.nextOffset' in the response to get the next page offset. Default: 0. Must be >= 0.")),
	)
	s.AddTool(alertsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_alerts")
		limit, offset := paginate.ParseParams(req.Params.Arguments)

		client := h.GetClient(ctx)
		alerts, err := client.ListAlerts(ctx)
		if err != nil {
			h.logger.Error("Failed to list alerts", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		var apiResponse types.APIAlertsResponse
		if err := json.Unmarshal(alerts, &apiResponse); err != nil {
			h.logger.Error("Failed to parse alerts response", zap.Error(err), zap.String("response", string(alerts)))
			return mcp.NewToolResultError("failed to parse alerts response: " + err.Error()), nil
		}

		// takes only meaningful data
		alertsList := make([]types.Alert, 0, len(apiResponse.Data))
		for _, apiAlert := range apiResponse.Data {
			alertsList = append(alertsList, types.Alert{
				Alertname: apiAlert.Labels.Alertname,
				RuleID:    apiAlert.Labels.RuleID,
				Severity:  apiAlert.Labels.Severity,
				StartsAt:  apiAlert.StartsAt,
				EndsAt:    apiAlert.EndsAt,
				State:     apiAlert.Status.State,
			})
		}

		total := len(alertsList)
		alertsArray := make([]any, len(alertsList))
		for i, v := range alertsList {
			alertsArray[i] = v
		}
		pagedAlerts := paginate.Array(alertsArray, offset, limit)

		resultJSON, err := paginate.Wrap(pagedAlerts, total, offset, limit)
		if err != nil {
			h.logger.Error("Failed to wrap alerts with pagination", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal response: " + err.Error()), nil
		}

		return mcp.NewToolResultText(string(resultJSON)), nil
	})

	getAlertTool := mcp.NewTool("signoz_get_alert",
		mcp.WithDescription("Get details of a specific alert rule by ruleId"),
		mcp.WithString("ruleId", mcp.Required(), mcp.Description("Alert ruleId")),
	)
	s.AddTool(getAlertTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ruleID, ok := req.Params.Arguments.(map[string]any)["ruleId"].(string)
		if !ok {
			h.logger.Warn("Invalid ruleId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "ruleId" must be a string. Example: {"ruleId": "0196634d-5d66-75c4-b778-e317f49dab7a"}`), nil
		}
		if ruleID == "" {
			h.logger.Warn("Empty ruleId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "ruleId" cannot be empty. Provide a valid alert rule ID (UUID format)`), nil
		}

		h.logger.Debug("Tool called: signoz_get_alert", zap.String("ruleId", ruleID))
		client := h.GetClient(ctx)
		respJSON, err := client.GetAlertByRuleID(ctx, ruleID)
		if err != nil {
			h.logger.Error("Failed to get alert", zap.String("ruleId", ruleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(respJSON)), nil
	})

	alertHistoryTool := mcp.NewTool("signoz_get_alert_history",
		mcp.WithDescription("Get alert history timeline for a specific rule. Defaults to last 6 hours if no time specified."),
		mcp.WithString("ruleId", mcp.Required(), mcp.Description("Alert rule ID")),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start timestamp in milliseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End timestamp in milliseconds (optional, defaults to now)")),
		mcp.WithString("offset", mcp.Description("Offset for pagination (default: 0)")),
		mcp.WithString("limit", mcp.Description("Limit number of results (default: 20)")),
		mcp.WithString("order", mcp.Description("Sort order: 'asc' or 'desc' (default: 'asc')")),
	)
	s.AddTool(alertHistoryTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		ruleID, ok := args["ruleId"].(string)
		if !ok || ruleID == "" {
			h.logger.Warn("Invalid or empty ruleId parameter", zap.Any("ruleId", args["ruleId"]))
			return mcp.NewToolResultError(`Parameter validation failed: "ruleId" must be a non-empty string. Example: {"ruleId": "0196634d-5d66-75c4-b778-e317f49dab7a", "timeRange": "24h"}`), nil
		}

		startStr, endStr := timeutil.GetTimestampsWithDefaults(args, "ms")

		var start, end int64
		if _, err := fmt.Sscanf(startStr, "%d", &start); err != nil {
			h.logger.Warn("Invalid start timestamp format", zap.String("start", startStr), zap.Error(err))
			return mcp.NewToolResultError(fmt.Sprintf(`Invalid "start" timestamp: "%s". Expected milliseconds since epoch (e.g., "1697385600000") or use "timeRange" parameter instead (e.g., "24h")`, startStr)), nil
		}
		if _, err := fmt.Sscanf(endStr, "%d", &end); err != nil {
			h.logger.Warn("Invalid end timestamp format", zap.String("end", endStr), zap.Error(err))
			return mcp.NewToolResultError(fmt.Sprintf(`Invalid "end" timestamp: "%s". Expected milliseconds since epoch (e.g., "1697472000000") or use "timeRange" parameter instead (e.g., "24h")`, endStr)), nil
		}

		_, offset := paginate.ParseParams(args)

		limit := 20
		if limitStr, ok := args["limit"].(string); ok && limitStr != "" {
			if limitInt, err := strconv.Atoi(limitStr); err != nil {
				h.logger.Warn("Invalid limit format", zap.String("limit", limitStr), zap.Error(err))
				return mcp.NewToolResultError(fmt.Sprintf(`Invalid "limit" value: "%s". Expected integer between 1-1000 (e.g., "20", "50", "100")`, limitStr)), nil
			} else if limitInt > 0 {
				limit = limitInt
			}
		}

		order := "asc"
		if orderStr, ok := args["order"].(string); ok && orderStr != "" {
			if orderStr == "asc" || orderStr == "desc" {
				order = orderStr
			} else {
				h.logger.Warn("Invalid order value", zap.String("order", orderStr))
				return mcp.NewToolResultError(fmt.Sprintf(`Invalid "order" value: "%s". Must be either "asc" or "desc"`, orderStr)), nil
			}
		}

		historyReq := types.AlertHistoryRequest{
			Start:  start,
			End:    end,
			Offset: offset,
			Limit:  limit,
			Order:  order,
			Filters: types.AlertHistoryFilters{
				Items: []interface{}{},
				Op:    "AND",
			},
		}

		h.logger.Debug("Tool called: signoz_get_alert_history",
			zap.String("ruleId", ruleID),
			zap.Int64("start", start),
			zap.Int64("end", end),
			zap.Int("offset", offset),
			zap.Int("limit", limit),
			zap.String("order", order))

		client := h.GetClient(ctx)
		respJSON, err := client.GetAlertHistory(ctx, ruleID, historyReq)
		if err != nil {
			h.logger.Error("Failed to get alert history",
				zap.String("ruleId", ruleID),
				zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(respJSON)), nil
	})

	createAlertRuleTool := mcp.NewTool("signoz_create_alert_rule",
		mcp.WithDescription("Create a new alert rule in SigNoz. The rule parameter must be a complete alert rule JSON object. Use signoz_get_alert to retrieve an existing rule as a template for the structure. Key fields: alert (name), alertType (METRIC_BASED_ALERT, LOGS_BASED_ALERT, TRACES_BASED_ALERT, EXCEPTIONS_BASED_ALERT), ruleType (threshold_rule, promql_rule), condition (with compositeQuery, op, target), labels (must include severity), preferredChannels, evalWindow, frequency."),
		mcp.WithObject("rule", mcp.Required(), mcp.Description("Complete alert rule JSON object")),
	)
	s.AddTool(createAlertRuleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_alert_rule")

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Warn("Invalid arguments payload type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}

		ruleObj, ok := args["rule"].(map[string]any)
		if !ok {
			h.logger.Warn("Invalid rule parameter type", zap.Any("type", args["rule"]))
			return mcp.NewToolResultError("rule parameter must be a JSON object"), nil
		}

		ruleJSON, err := json.Marshal(ruleObj)
		if err != nil {
			h.logger.Error("Failed to marshal rule object", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal rule object: " + err.Error()), nil
		}

		client := h.GetClient(ctx)
		result, err := client.CreateAlertRule(ctx, ruleJSON)
		if err != nil {
			h.logger.Error("Failed to create alert rule", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	updateAlertRuleTool := mcp.NewTool("signoz_update_alert_rule",
		mcp.WithDescription("Update an existing alert rule. Requires the rule ID and a complete alert rule JSON object representing the post-update state. Use signoz_get_alert to retrieve the current rule configuration first, modify it, then pass it here."),
		mcp.WithString("ruleId", mcp.Required(), mcp.Description("Alert rule ID to update")),
		mcp.WithObject("rule", mcp.Required(), mcp.Description("Complete alert rule JSON object representing the post-update state")),
	)
	s.AddTool(updateAlertRuleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_alert_rule")

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Warn("Invalid arguments payload type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}

		ruleID, ok := args["ruleId"].(string)
		if !ok {
			h.logger.Warn("Invalid ruleId parameter type", zap.Any("type", args["ruleId"]))
			return mcp.NewToolResultError(`Parameter validation failed: "ruleId" must be a string. Example: {"ruleId": "0196634d-5d66-75c4-b778-e317f49dab7a"}`), nil
		}
		if ruleID == "" {
			h.logger.Warn("Empty ruleId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "ruleId" cannot be empty. Provide a valid alert rule ID`), nil
		}

		ruleObj, ok := args["rule"].(map[string]any)
		if !ok {
			h.logger.Warn("Invalid rule parameter type", zap.Any("type", args["rule"]))
			return mcp.NewToolResultError("rule parameter must be a JSON object"), nil
		}

		ruleJSON, err := json.Marshal(ruleObj)
		if err != nil {
			h.logger.Error("Failed to marshal rule object", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal rule object: " + err.Error()), nil
		}

		client := h.GetClient(ctx)
		err = client.UpdateAlertRule(ctx, ruleID, ruleJSON)
		if err != nil {
			h.logger.Error("Failed to update alert rule", zap.String("ruleId", ruleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText("alert rule updated successfully"), nil
	})

	deleteAlertRuleTool := mcp.NewTool("signoz_delete_alert_rule",
		mcp.WithDescription("Delete an alert rule by ID. This action is irreversible. Use signoz_list_alerts to find rule IDs."),
		mcp.WithString("ruleId", mcp.Required(), mcp.Description("Alert rule ID to delete")),
	)
	s.AddTool(deleteAlertRuleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ruleID, ok := req.Params.Arguments.(map[string]any)["ruleId"].(string)
		if !ok {
			h.logger.Warn("Invalid ruleId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "ruleId" must be a string. Example: {"ruleId": "0196634d-5d66-75c4-b778-e317f49dab7a"}`), nil
		}
		if ruleID == "" {
			h.logger.Warn("Empty ruleId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "ruleId" cannot be empty. Provide a valid alert rule ID`), nil
		}

		h.logger.Debug("Tool called: signoz_delete_alert_rule", zap.String("ruleId", ruleID))
		client := h.GetClient(ctx)
		err := client.DeleteAlertRule(ctx, ruleID)
		if err != nil {
			h.logger.Error("Failed to delete alert rule", zap.String("ruleId", ruleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText("alert rule deleted"), nil
	})
}

func (h *Handler) RegisterDashboardHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering dashboard handlers")

	tool := mcp.NewTool("signoz_list_dashboards",
		mcp.WithDescription("List all dashboards from SigNoz (returns summary with name, UUID, description, tags, and timestamps). IMPORTANT: This tool supports pagination using 'limit' and 'offset' parameters. The response includes 'pagination' metadata with 'total', 'hasMore', and 'nextOffset' fields. When searching for a specific dashboard, ALWAYS check 'pagination.hasMore' - if true, continue paginating through all pages using 'nextOffset' until you find the item or 'hasMore' is false. Never conclude an item doesn't exist until you've checked all pages. Default: limit=50, offset=0."),
		mcp.WithString("limit", mcp.Description("Maximum number of dashboards to return per page. Use this to paginate through large result sets. Default: 50. Example: '50' for 50 results, '100' for 100 results. Must be greater than 0.")),
		mcp.WithString("offset", mcp.Description("Number of results to skip before returning results. Use for pagination: offset=0 for first page, offset=50 for second page (if limit=50), offset=100 for third page, etc. Check 'pagination.nextOffset' in the response to get the next page offset. Default: 0. Must be >= 0.")),
	)

	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_dashboards")
		limit, offset := paginate.ParseParams(req.Params.Arguments)

		client := h.GetClient(ctx)
		result, err := client.ListDashboards(ctx)
		if err != nil {
			h.logger.Error("Failed to list dashboards", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		var dashboards map[string]any
		if err := json.Unmarshal(result, &dashboards); err != nil {
			h.logger.Error("Failed to parse dashboards response", zap.Error(err))
			return mcp.NewToolResultError("failed to parse response: " + err.Error()), nil
		}

		data, ok := dashboards["data"].([]any)
		if !ok {
			h.logger.Error("Invalid dashboards response format", zap.Any("data", dashboards["data"]))
			return mcp.NewToolResultError("invalid response format: expected data array"), nil
		}

		total := len(data)
		pagedData := paginate.Array(data, offset, limit)

		resultJSON, err := paginate.Wrap(pagedData, total, offset, limit)
		if err != nil {
			h.logger.Error("Failed to wrap dashboards with pagination", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal response: " + err.Error()), nil
		}

		return mcp.NewToolResultText(string(resultJSON)), nil
	})

	getDashboardTool := mcp.NewTool("signoz_get_dashboard",
		mcp.WithDescription("Get full details of a specific dashboard by UUID (returns complete dashboard configuration with all panels and queries)"),
		mcp.WithString("uuid", mcp.Required(), mcp.Description("Dashboard UUID")),
	)

	s.AddTool(getDashboardTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		uuid, ok := req.Params.Arguments.(map[string]any)["uuid"].(string)
		if !ok {
			h.logger.Warn("Invalid uuid parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "uuid" must be a string. Example: {"uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}`), nil
		}
		if uuid == "" {
			h.logger.Warn("Empty uuid parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "uuid" cannot be empty. Provide a valid dashboard UUID. Use signoz_list_dashboards tool to see available dashboards.`), nil
		}

		h.logger.Debug("Tool called: signoz_get_dashboard", zap.String("uuid", uuid))
		client := h.GetClient(ctx)
		data, err := client.GetDashboard(ctx, uuid)
		if err != nil {
			h.logger.Error("Failed to get dashboard", zap.String("uuid", uuid), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})

	createDashboardTool := mcp.NewTool(
		"signoz_create_dashboard",
		mcp.WithDescription(
			"Creates a new monitoring dashboard based on the provided title, layout, and widget configuration. "+
				"CRITICAL: You MUST read these resources BEFORE generating any dashboard output:\n"+
				"1. signoz://dashboard/instructions - REQUIRED: Dashboard structure and basics\n"+
				"2. signoz://dashboard/widgets-instructions - REQUIRED: Widget configuration rules\n"+
				"3. signoz://dashboard/widgets-examples - REQUIRED: Complete widget examples with all required fields\n\n"+
				"QUERY-SPECIFIC RESOURCES (read based on query type used):\n"+
				"- For PromQL queries: signoz://dashboard/promql-example\n"+
				"- For Query Builder queries: signoz://dashboard/query-builder-example\n"+
				"- For ClickHouse SQL on logs: signoz://dashboard/clickhouse-schema-for-logs + signoz://dashboard/clickhouse-logs-example\n"+
				"- For ClickHouse SQL on metrics: signoz://dashboard/clickhouse-schema-for-metrics + signoz://dashboard/clickhouse-metrics-example\n"+
				"- For ClickHouse SQL on traces: signoz://dashboard/clickhouse-schema-for-traces + signoz://dashboard/clickhouse-traces-example\n\n"+
				"IMPORTANT: The widgets-examples resource contains complete, working widget configurations. "+
				"You must consult it to ensure all required fields (id, panelTypes, title, query, selectedLogFields, selectedTracesFields, thresholds, contextLinks) are properly populated.",
		),
		mcp.WithInputSchema[types.Dashboard](),
	)

	s.AddTool(createDashboardTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rawConfig, ok := req.Params.Arguments.(map[string]any)

		if !ok || len(rawConfig) == 0 {
			h.logger.Warn("Received empty or invalid arguments map.")
			return mcp.NewToolResultError(`Parameter validation failed: The dashboard configuration object is empty or improperly formatted.`), nil
		}

		configJSON, err := json.Marshal(rawConfig)
		if err != nil {
			h.logger.Error("Failed to unmarshal raw configuration", zap.Error(err))
			return mcp.NewToolResultError(
				fmt.Sprintf("Could not decode raw configuration. Error: %s", err.Error()),
			), nil
		}

		var dashboardConfig types.Dashboard
		if err := json.Unmarshal(configJSON, &dashboardConfig); err != nil {
			return mcp.NewToolResultError(
				fmt.Sprintf("Parameter decoding error: The provided JSON structure for the dashboard configuration is invalid. Error details: %s", err.Error()),
			), nil
		}

		h.logger.Debug("Tool called: signoz_create_dashboard", zap.String("title", dashboardConfig.Title))
		client := h.GetClient(ctx)
		data, err := client.CreateDashboard(ctx, dashboardConfig)

		if err != nil {
			h.logger.Error("Failed to create dashboard in SigNoz", zap.Error(err))
			return mcp.NewToolResultError(fmt.Sprintf("SigNoz API Error: %s", err.Error())), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	})

	updateDashboardTool := mcp.NewTool(
		"signoz_update_dashboard",
		mcp.WithDescription(
			"Update an existing dashboard by supplying its UUID along with a fully assembled dashboard JSON object.\n\n"+
				"MANDATORY FIRST STEP: Read signoz://dashboard/widgets-examples before doing ANYTHING else. This is NON-NEGOTIABLE.\n\n"+
				"The provided object must represent the complete post-update state, combining the current dashboard data and the intended modifications.\n\n"+
				"REQUIRED RESOURCES (read ALL before generating output):\n"+
				"1. signoz://dashboard/instructions\n"+
				"2. signoz://dashboard/widgets-instructions\n"+
				"3. signoz://dashboard/widgets-examples ← CRITICAL: Shows complete widget field structure\n\n"+
				"CONDITIONAL RESOURCES (based on query type):\n"+
				"• PromQL → signoz://dashboard/promql-example\n"+
				"• Query Builder → signoz://dashboard/query-builder-example\n"+
				"• ClickHouse Logs → signoz://dashboard/clickhouse-schema-for-logs + clickhouse-logs-example\n"+
				"• ClickHouse Metrics → signoz://dashboard/clickhouse-schema-for-metrics + clickhouse-metrics-example\n"+
				"• ClickHouse Traces → signoz://dashboard/clickhouse-schema-for-traces + clickhouse-traces-example\n\n"+
				"WARNING: Failing to consult widgets-examples will result in incomplete widget configurations missing required fields "+
				"(id, panelTypes, title, query, selectedLogFields, selectedTracesFields, thresholds, contextLinks).",
		),
		mcp.WithInputSchema[types.UpdateDashboardInput](),
	)

	s.AddTool(updateDashboardTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rawConfig, ok := req.Params.Arguments.(map[string]any)

		if !ok || len(rawConfig) == 0 {
			h.logger.Warn("Received empty or invalid arguments map from Claude.")
			return mcp.NewToolResultError(`Parameter validation failed: The dashboard configuration object is empty or improperly formatted.`), nil
		}

		configJSON, err := json.Marshal(rawConfig)
		if err != nil {
			h.logger.Error("Failed to unmarshal raw configuration", zap.Error(err))
			return mcp.NewToolResultError(
				fmt.Sprintf("Could not decode raw configuration. Error: %s", err.Error()),
			), nil
		}

		var updateDashboardConfig types.UpdateDashboardInput
		if err := json.Unmarshal(configJSON, &updateDashboardConfig); err != nil {
			return mcp.NewToolResultError(
				fmt.Sprintf("Parameter decoding error: The provided JSON structure for the dashboard configuration is invalid. Error details: %s", err.Error()),
			), nil
		}

		if updateDashboardConfig.UUID == "" {
			h.logger.Warn("Empty uuid parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "uuid" cannot be empty. Provide a valid dashboard UUID. Use list_dashboards tool to see available dashboards.`), nil
		}

		h.logger.Debug("Tool called: signoz_update_dashboard", zap.String("title", updateDashboardConfig.Dashboard.Title))
		client := h.GetClient(ctx)
		err = client.UpdateDashboard(ctx, updateDashboardConfig.UUID, updateDashboardConfig.Dashboard)

		if err != nil {
			h.logger.Error("Failed to update dashboard in SigNoz", zap.Error(err))
			return mcp.NewToolResultError(fmt.Sprintf("SigNoz API Error: %s", err.Error())), nil
		}

		return mcp.NewToolResultText("dashboard updated"), nil
	})

	deleteDashboardTool := mcp.NewTool("signoz_delete_dashboard",
		mcp.WithDescription("Delete a dashboard by UUID. This action is irreversible. Use signoz_list_dashboards to find dashboard UUIDs."),
		mcp.WithString("uuid", mcp.Required(), mcp.Description("Dashboard UUID to delete")),
	)

	s.AddTool(deleteDashboardTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		uuid, ok := req.Params.Arguments.(map[string]any)["uuid"].(string)
		if !ok {
			h.logger.Warn("Invalid uuid parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "uuid" must be a string. Example: {"uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}`), nil
		}
		if uuid == "" {
			h.logger.Warn("Empty uuid parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "uuid" cannot be empty. Provide a valid dashboard UUID. Use signoz_list_dashboards tool to see available dashboards.`), nil
		}

		h.logger.Debug("Tool called: signoz_delete_dashboard", zap.String("uuid", uuid))
		client := h.GetClient(ctx)
		err := client.DeleteDashboard(ctx, uuid)
		if err != nil {
			h.logger.Error("Failed to delete dashboard", zap.String("uuid", uuid), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("dashboard deleted"), nil
	})

	// resources for create and update dashboard
	clickhouseLogsSchemaResource := mcp.NewResource(
		"signoz://dashboard/clickhouse-schema-for-logs",
		"ClickHouse Logs Schema",
		mcp.WithResourceDescription("ClickHouse schema for logs_v2, logs_v2_resource, tag_attributes_v2 and their distributed counterparts. requires dashboard instructions at signoz://dashboard/instructions"),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(clickhouseLogsSchemaResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.LogsSchema,
			},
		}, nil
	})

	clickhouseLogsExample := mcp.NewResource(
		"signoz://dashboard/clickhouse-logs-example",
		"Clickhouse Examples for logs",
		mcp.WithResourceDescription("ClickHouse SQL query examples for SigNoz logs. Includes resource filter patterns (CTE), timeseries queries, value queries, common use cases (Kubernetes clusters, error logs by service), and key patterns for timestamp filtering, attribute access (resource vs standard, indexed vs non-indexed), severity filters, variables, and performance optimization tips."),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(clickhouseLogsExample, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.ClickhouseSqlQueryForLogs,
			},
		}, nil
	})

	clickhouseMetricsSchemaResource := mcp.NewResource(
		"signoz://dashboard/clickhouse-schema-for-metrics",
		"ClickHouse Metrics Schema",
		mcp.WithResourceDescription("ClickHouse schema for samples_v4, exp_hist, time_series_v4 (and 6hrs/1day variants) and their distributed counterparts. requires dashboard instructions at signoz://dashboard/instructions"),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(clickhouseMetricsSchemaResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.MetricsSchema,
			},
		}, nil
	})

	clickhouseMetricsExample := mcp.NewResource(
		"signoz://dashboard/clickhouse-metrics-example",
		"Clickhouse Examples for Metrics",
		mcp.WithResourceDescription("ClickHouse SQL query examples for SigNoz metrics. Includes basic queries , rate calculation patterns for counter metrics (using lagInFrame and runningDifference), error rate calculations (ratio of two metrics), histogram quantile queries for latency percentiles (P95, P99), and key patterns for time series table selection by granularity, timestamp filtering, label filtering, time interval aggregation, variables, and performance optimization"),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(clickhouseMetricsExample, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.ClickhouseSqlQueryForMetrics,
			},
		}, nil
	})

	clickhouseTracesSchemaResource := mcp.NewResource(
		"signoz://dashboard/clickhouse-schema-for-traces",
		"ClickHouse Traces Schema",
		mcp.WithResourceDescription("ClickHouse schema for signoz_index_v3, signoz_spans, signoz_error_index_v2, traces_v3_resource, dependency_graph_minutes_v2, trace_summary, top_level_operations and their distributed counterparts. requires dashboard instructions at signoz://dashboard/instructions"),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(clickhouseTracesSchemaResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.TracesSchema,
			},
		}, nil
	})

	clickhouseTracesExample := mcp.NewResource(
		"signoz://dashboard/clickhouse-traces-example",
		"Clickhouse Examples for Traces",
		mcp.WithResourceDescription("ClickHouse SQL examples for SigNoz traces: resource filters, timeseries/value/table queries, span event extraction, latency analysis, and performance tips."),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(clickhouseTracesExample, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.ClickhouseSqlQueryForTraces,
			},
		}, nil
	})

	promqlExample := mcp.NewResource(
		"signoz://dashboard/promql-example",
		"Promql Examples",
		mcp.WithResourceDescription("PromQL guide for SigNoz: critical syntax rules for OpenTelemetry metrics with dots, formatting patterns, examples by metric type, and error prevention."),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(promqlExample, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.PromqlQuery,
			},
		}, nil
	})

	queryBuilderExample := mcp.NewResource(
		"signoz://dashboard/query-builder-example",
		"Query Builder Examples",
		mcp.WithResourceDescription("SigNoz Query Builder reference: CRITICAL OpenTelemetry metric naming conventions (dot vs underscore suffixes), filtering, aggregation, search syntax, operators, field existence behavior, full-text search, functions, advanced examples, and best practices."),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(queryBuilderExample, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.Querybuilder,
			},
		}, nil
	})

	dashboardInstructions := mcp.NewResource(
		"signoz://dashboard/instructions",
		"Dashboard Basic Instructions",
		mcp.WithResourceDescription("SigNoz dashboard basics: title, tags, description, and comprehensive variable configuration rules (types, properties, referencing, chaining)."),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(dashboardInstructions, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.Basics,
			},
		}, nil
	})

	widgetsInstructions := mcp.NewResource(
		"signoz://dashboard/widgets-instructions",
		"Dashboard Basic Instructions",
		mcp.WithResourceDescription("SigNoz dashboard widgets: 7 panel types (Bar, Histogram, List, Pie, Table, Timeseries, Value) with use cases, configuration options, and critical layout rules (grid coordinates, dimensions, legends)."),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(widgetsInstructions, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.WidgetsInstructions,
			},
		}, nil
	})

	widgetsExamplesResource := mcp.NewResource(
		"signoz://dashboard/widgets-examples",
		"Dashboard Widgets Examples",
		mcp.WithResourceDescription("Basic Example widgets"),
		mcp.WithMIMEType("text/plain"),
	)

	s.AddResource(widgetsExamplesResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "text/plain",
				Text:     dashboard.WidgetExamples,
			},
		}, nil
	})

}

func (h *Handler) RegisterServiceHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering service handlers")

	listTool := mcp.NewTool("signoz_list_services",
		mcp.WithDescription("List all services in SigNoz. Defaults to last 6 hours if no time specified. IMPORTANT: This tool supports pagination using 'limit' and 'offset' parameters. The response includes 'pagination' metadata with 'total', 'hasMore', and 'nextOffset' fields. When searching for a specific service, ALWAYS check 'pagination.hasMore' - if true, continue paginating through all pages using 'nextOffset' until you find the item or 'hasMore' is false. Never conclude an item doesn't exist until you've checked all pages. Default: limit=50, offset=0."),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in nanoseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in nanoseconds (optional, defaults to now)")),
		mcp.WithString("limit", mcp.Description("Maximum number of services to return per page. Use this to paginate through large result sets. Default: 50. Example: '50' for 50 results, '100' for 100 results. Must be greater than 0.")),
		mcp.WithString("offset", mcp.Description("Number of results to skip before returning results. Use for pagination: offset=0 for first page, offset=50 for second page (if limit=50), offset=100 for third page, etc. Check 'pagination.nextOffset' in the response to get the next page offset. Default: 0. Must be >= 0.")),
	)

	s.AddTool(listTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		start, end := timeutil.GetTimestampsWithDefaults(args, "ns")
		limit, offset := paginate.ParseParams(req.Params.Arguments)

		h.logger.Debug("Tool called: signoz_list_services", zap.String("start", start), zap.String("end", end), zap.Int("limit", limit), zap.Int("offset", offset))
		client := h.GetClient(ctx)
		result, err := client.ListServices(ctx, start, end)
		if err != nil {
			h.logger.Error("Failed to list services", zap.String("start", start), zap.String("end", end), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		var services []any
		if err := json.Unmarshal(result, &services); err != nil {
			h.logger.Error("Failed to parse services response", zap.Error(err))
			return mcp.NewToolResultError("failed to parse response: " + err.Error()), nil
		}

		total := len(services)
		pagedServices := paginate.Array(services, offset, limit)

		resultJSON, err := paginate.Wrap(pagedServices, total, offset, limit)
		if err != nil {
			h.logger.Error("Failed to wrap services with pagination", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal response: " + err.Error()), nil
		}

		return mcp.NewToolResultText(string(resultJSON)), nil
	})

	getOpsTool := mcp.NewTool("signoz_get_service_top_operations",
		mcp.WithDescription("Get top operations for a specific service. Defaults to last 6 hours if no time specified."),
		mcp.WithString("service", mcp.Required(), mcp.Description("Service name")),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in nanoseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in nanoseconds (optional, defaults to now)")),
		mcp.WithString("tags", mcp.Description("Optional tags JSON array")),
	)

	s.AddTool(getOpsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		service, ok := args["service"].(string)
		if !ok {
			h.logger.Warn("Invalid service parameter type", zap.Any("type", args["service"]))
			return mcp.NewToolResultError(`Parameter validation failed: "service" must be a string. Example: {"service": "frontend-api", "timeRange": "1h"}`), nil
		}
		if service == "" {
			h.logger.Warn("Empty service parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "service" cannot be empty. Provide a valid service name. Use signoz_list_services tool to see available services.`), nil
		}

		start, end := timeutil.GetTimestampsWithDefaults(args, "ns")

		var tags json.RawMessage
		if t, ok := args["tags"].(string); ok && t != "" {
			tags = json.RawMessage(t)
		} else {
			tags = json.RawMessage("[]")
		}

		h.logger.Debug("Tool called: signoz_get_service_top_operations",
			zap.String("start", start),
			zap.String("end", end),
			zap.String("service", service))

		client := h.GetClient(ctx)
		result, err := client.GetServiceTopOperations(ctx, start, end, service, tags)
		if err != nil {
			h.logger.Error("Failed to get service top operations",
				zap.String("start", start),
				zap.String("end", end),
				zap.String("service", service),
				zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterQueryBuilderV5Handlers(s *server.MCPServer) {
	h.logger.Debug("Registering query builder v5 handlers")

	// SigNoz Query Builder v5 tool - LLM builds structured query JSON and executes it
	executeQuery := mcp.NewTool("signoz_execute_builder_query",
		mcp.WithDescription("Execute a SigNoz Query Builder v5 query. The LLM should build the complete structured query JSON matching SigNoz's Query Builder v5 format. Example structure: {\"schemaVersion\":\"v1\",\"start\":1756386047000,\"end\":1756387847000,\"requestType\":\"raw\",\"compositeQuery\":{\"queries\":[{\"type\":\"builder_query\",\"spec\":{\"name\":\"A\",\"signal\":\"traces\",\"disabled\":false,\"limit\":10,\"offset\":0,\"order\":[{\"key\":{\"name\":\"timestamp\"},\"direction\":\"desc\"}],\"having\":{\"expression\":\"\"},\"selectFields\":[{\"name\":\"service.name\",\"fieldDataType\":\"string\",\"signal\":\"traces\",\"fieldContext\":\"resource\"},{\"name\":\"duration_nano\",\"fieldDataType\":\"\",\"signal\":\"traces\",\"fieldContext\":\"span\"}]}}]},\"formatOptions\":{\"formatTableResultForUI\":false,\"fillGaps\":false},\"variables\":{}}. See docs: https://signoz.io/docs/userguide/query-builder-v5/"),
		mcp.WithObject("query", mcp.Required(), mcp.Description("Complete SigNoz Query Builder v5 JSON object with schemaVersion, start, end, requestType, compositeQuery, formatOptions, and variables")),
	)

	s.AddTool(executeQuery, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_execute_builder_query")

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Warn("Invalid arguments payload type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}

		queryObj, ok := args["query"].(map[string]any)
		if !ok {
			h.logger.Warn("Invalid query parameter type", zap.Any("type", args["query"]))
			return mcp.NewToolResultError("query parameter must be a JSON object"), nil
		}

		queryJSON, err := json.Marshal(queryObj)
		if err != nil {
			h.logger.Error("Failed to marshal query object", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal query object: " + err.Error()), nil
		}

		var queryPayload types.QueryPayload
		if err := json.Unmarshal(queryJSON, &queryPayload); err != nil {
			h.logger.Error("Failed to unmarshal query payload", zap.Error(err))
			return mcp.NewToolResultError("invalid query payload structure: " + err.Error()), nil
		}

		if err := queryPayload.Validate(); err != nil {
			h.logger.Error("Query validation failed", zap.Error(err))
			return mcp.NewToolResultError("query validation error: " + err.Error()), nil
		}

		finalQueryJSON, err := json.Marshal(queryPayload)
		if err != nil {
			h.logger.Error("Failed to marshal validated query payload", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal validated query payload: " + err.Error()), nil
		}

		client := h.GetClient(ctx)
		data, err := client.QueryBuilderV5(ctx, finalQueryJSON)
		if err != nil {
			h.logger.Error("Failed to execute query builder v5", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		h.logger.Debug("Successfully executed query builder v5")
		return mcp.NewToolResultText(string(data)), nil
	})
}

func (h *Handler) RegisterLogsHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering logs handlers")

	listLogViewsTool := mcp.NewTool("signoz_list_log_views",
		mcp.WithDescription("List all saved log views from SigNoz (returns summary with name, ID, description, and query details). IMPORTANT: This tool supports pagination using 'limit' and 'offset' parameters. The response includes 'pagination' metadata with 'total', 'hasMore', and 'nextOffset' fields. When searching for a specific log view, ALWAYS check 'pagination.hasMore' - if true, continue paginating through all pages using 'nextOffset' until you find the item or 'hasMore' is false. Never conclude an item doesn't exist until you've checked all pages. Default: limit=50, offset=0."),
		mcp.WithString("limit", mcp.Description("Maximum number of views to return per page. Use this to paginate through large result sets. Default: 50. Example: '50' for 50 results, '100' for 100 results. Must be greater than 0.")),
		mcp.WithString("offset", mcp.Description("Number of results to skip before returning results. Use for pagination: offset=0 for first page, offset=50 for second page (if limit=50), offset=100 for third page, etc. Check 'pagination.nextOffset' in the response to get the next page offset. Default: 0. Must be >= 0.")),
	)

	s.AddTool(listLogViewsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_log_views")
		limit, offset := paginate.ParseParams(req.Params.Arguments)

		client := h.GetClient(ctx)
		result, err := client.ListLogViews(ctx)
		if err != nil {
			h.logger.Error("Failed to list log views", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		var logViews map[string]any
		if err := json.Unmarshal(result, &logViews); err != nil {
			h.logger.Error("Failed to parse log views response", zap.Error(err))
			return mcp.NewToolResultError("failed to parse response: " + err.Error()), nil
		}

		data, ok := logViews["data"].([]any)
		if !ok {
			// data may be null when no views exist
			if logViews["data"] == nil {
				data = []any{}
			} else {
				h.logger.Error("Invalid log views response format", zap.Any("data", logViews["data"]))
				return mcp.NewToolResultError("invalid response format: expected data array"), nil
			}
		}

		total := len(data)
		pagedData := paginate.Array(data, offset, limit)

		resultJSON, err := paginate.Wrap(pagedData, total, offset, limit)
		if err != nil {
			h.logger.Error("Failed to wrap log views with pagination", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal response: " + err.Error()), nil
		}

		return mcp.NewToolResultText(string(resultJSON)), nil
	})

	getLogViewTool := mcp.NewTool("signoz_get_log_view",
		mcp.WithDescription("Get full details of a specific log view by ID (returns complete log view configuration with query structure)"),
		mcp.WithString("viewId", mcp.Required(), mcp.Description("Log view ID")),
	)

	s.AddTool(getLogViewTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		viewID, ok := req.Params.Arguments.(map[string]any)["viewId"].(string)
		if !ok {
			h.logger.Warn("Invalid viewId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "viewId" must be a string. Example: {"viewId": "error-logs-view-123"}`), nil
		}
		if viewID == "" {
			h.logger.Warn("Empty viewId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "viewId" cannot be empty. Provide a valid log view ID. Use signoz_list_log_views tool to see available log views.`), nil
		}

		h.logger.Debug("Tool called: signoz_get_log_view", zap.String("viewId", viewID))
		client := h.GetClient(ctx)
		data, err := client.GetLogView(ctx, viewID)
		if err != nil {
			h.logger.Error("Failed to get log view", zap.String("viewId", viewID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})

	getLogsForAlertTool := mcp.NewTool("signoz_get_logs_for_alert",
		mcp.WithDescription("Get logs related to a specific alert (automatically determines time range and service from alert details)"),
		mcp.WithString("alertId", mcp.Required(), mcp.Description("Alert rule ID")),
		mcp.WithString("timeRange", mcp.Description("Time range around alert (optional). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '15m', '30m', '1h', '2h', '6h'. Defaults to '1h' if not provided.")),
		mcp.WithString("limit", mcp.Description("Maximum number of logs to return (default: 100)")),
		mcp.WithString("offset", mcp.Description("Offset for pagination (default: 0)")),
	)

	s.AddTool(getLogsForAlertTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		alertID, ok := args["alertId"].(string)
		if !ok || alertID == "" {
			return mcp.NewToolResultError(`Parameter validation failed: "alertId" must be a non-empty string. Example: {"alertId": "0196634d-5d66-75c4-b778-e317f49dab7a", "timeRange": "1h", "limit": "50"}`), nil
		}

		timeRange := "1h"
		if tr, ok := args["timeRange"].(string); ok && tr != "" {
			timeRange = tr
		}

		limit := 100
		if limitStr, ok := args["limit"].(string); ok && limitStr != "" {
			if limitInt, err := strconv.Atoi(limitStr); err == nil {
				limit = limitInt
			}
		}

		_, offset := paginate.ParseParams(req.Params.Arguments)

		h.logger.Debug("Tool called: signoz_get_logs_for_alert", zap.String("alertId", alertID))
		client := h.GetClient(ctx)
		alertData, err := client.GetAlertByRuleID(ctx, alertID)
		if err != nil {
			h.logger.Error("Failed to get alert details", zap.String("alertId", alertID), zap.Error(err))
			return mcp.NewToolResultError("failed to get alert details: " + err.Error()), nil
		}

		var alertResponse map[string]interface{}
		if err := json.Unmarshal(alertData, &alertResponse); err != nil {
			h.logger.Error("Failed to parse alert data", zap.Error(err))
			return mcp.NewToolResultError("failed to parse alert data: " + err.Error()), nil
		}

		serviceName := ""
		if data, ok := alertResponse["data"].(map[string]interface{}); ok {
			if labels, ok := data["labels"].(map[string]interface{}); ok {
				if service, ok := labels["service_name"].(string); ok {
					serviceName = service
				} else if service, ok := labels["service"].(string); ok {
					serviceName = service
				}
			}
		}

		now := time.Now()
		startTime := now.Add(-1 * time.Hour).UnixMilli()
		endTime := now.UnixMilli()

		if duration, err := timeutil.ParseTimeRange(timeRange); err == nil {
			startTime = now.Add(-duration).UnixMilli()
		}

		filterExpression := "severity_text IN ('ERROR', 'WARN', 'FATAL')"
		if serviceName != "" {
			filterExpression += fmt.Sprintf(" AND service.name in ['%s']", serviceName)
		}

		queryPayload := types.BuildLogsQueryPayload(startTime, endTime, filterExpression, limit, offset)

		queryJSON, err := json.Marshal(queryPayload)
		if err != nil {
			h.logger.Error("Failed to marshal query payload", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal query payload: " + err.Error()), nil
		}

		result, err := client.QueryBuilderV5(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to get logs for alert", zap.String("alertId", alertID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	getErrorLogsTool := mcp.NewTool("signoz_get_error_logs",
		mcp.WithDescription("Get logs with ERROR or FATAL severity. Defaults to last 6 hours if no time specified."),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in milliseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in milliseconds (optional, defaults to now)")),
		mcp.WithString("service", mcp.Description("Optional service name to filter by")),
		mcp.WithString("limit", mcp.Description("Maximum number of logs to return (default: 25, max: 200)")),
		mcp.WithString("offset", mcp.Description("Offset for pagination (default: 0)")),
	)

	s.AddTool(getErrorLogsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		start, end := timeutil.GetTimestampsWithDefaults(args, "ms")

		limit := 25
		if limitStr, ok := args["limit"].(string); ok && limitStr != "" {
			if limitInt, err := strconv.Atoi(limitStr); err == nil {
				if limitInt > 200 {
					limit = 200
				} else if limitInt < 1 {
					limit = 1
				} else {
					limit = limitInt
				}
			}
		}

		_, offset := paginate.ParseParams(req.Params.Arguments)

		filterExpression := "severity_text IN ('ERROR', 'FATAL')"

		if service, ok := args["service"].(string); ok && service != "" {
			filterExpression += fmt.Sprintf(" AND service.name in ['%s']", service)
		}

		var startTime, endTime int64
		if err := json.Unmarshal([]byte(start), &startTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "start" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, start)), nil
		}
		if err := json.Unmarshal([]byte(end), &endTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "end" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, end)), nil
		}

		queryPayload := types.BuildLogsQueryPayload(startTime, endTime, filterExpression, limit, offset)

		queryJSON, err := json.Marshal(queryPayload)
		if err != nil {
			h.logger.Error("Failed to marshal query payload", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal query payload: " + err.Error()), nil
		}

		h.logger.Debug("Tool called: signoz_get_error_logs", zap.String("start", start), zap.String("end", end))
		client := h.GetClient(ctx)
		result, err := client.QueryBuilderV5(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to get error logs", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	searchLogsByServiceTool := mcp.NewTool("signoz_search_logs_by_service",
		mcp.WithDescription("Search logs for a specific service. Defaults to last 6 hours if no time specified."),
		mcp.WithString("service", mcp.Required(), mcp.Description("Service name to search logs for")),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in milliseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in milliseconds (optional, defaults to now)")),
		mcp.WithString("severity", mcp.Description("Log severity filter (DEBUG, INFO, WARN, ERROR, FATAL)")),
		mcp.WithString("searchText", mcp.Description("Text to search for in log body")),
		mcp.WithString("limit", mcp.Description("Maximum number of logs to return (default: 100)")),
		mcp.WithString("offset", mcp.Description("Offset for pagination (default: 0)")),
	)

	s.AddTool(searchLogsByServiceTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		service, ok := args["service"].(string)
		if !ok || service == "" {
			return mcp.NewToolResultError(`Parameter validation failed: "service" must be a non-empty string. Example: {"service": "consumer-svc-1", "searchText": "error", "timeRange": "1h", "limit": "50"}`), nil
		}

		start, end := timeutil.GetTimestampsWithDefaults(args, "ms")

		limit := 100
		if limitStr, ok := args["limit"].(string); ok && limitStr != "" {
			if limitInt, err := strconv.Atoi(limitStr); err == nil {
				limit = limitInt
			}
		}

		_, offset := paginate.ParseParams(req.Params.Arguments)

		filterExpression := fmt.Sprintf("service.name in ['%s']", service)

		if severity, ok := args["severity"].(string); ok && severity != "" {
			filterExpression += fmt.Sprintf(" AND severity_text = '%s'", severity)
		}

		if searchText, ok := args["searchText"].(string); ok && searchText != "" {
			filterExpression += fmt.Sprintf(" AND body CONTAINS '%s'", searchText)
		}

		var startTime, endTime int64
		if err := json.Unmarshal([]byte(start), &startTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "start" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, start)), nil
		}
		if err := json.Unmarshal([]byte(end), &endTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "end" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, end)), nil
		}

		queryPayload := types.BuildLogsQueryPayload(startTime, endTime, filterExpression, limit, offset)

		queryJSON, err := json.Marshal(queryPayload)
		if err != nil {
			h.logger.Error("Failed to marshal query payload", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal query payload: " + err.Error()), nil
		}

		h.logger.Debug("Tool called: signoz_search_logs_by_service", zap.String("service", service), zap.String("start", start), zap.String("end", end))
		client := h.GetClient(ctx)
		result, err := client.QueryBuilderV5(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to search logs by service", zap.String("service", service), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	getLogsAvailableFieldsTool := mcp.NewTool("signoz_get_logs_available_fields",
		mcp.WithDescription("Get available field names for log queries"),
		mcp.WithString("searchText", mcp.Description("Search text to filter available fields (optional)")),
	)

	s.AddTool(getLogsAvailableFieldsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		searchText := ""
		if search, ok := args["searchText"].(string); ok && search != "" {
			searchText = search
		}

		h.logger.Debug("Tool called: signoz_get_logs_available_fields", zap.String("searchText", searchText))
		client := h.GetClient(ctx)
		result, err := client.GetLogsAvailableFields(ctx, searchText)
		if err != nil {
			h.logger.Error("Failed to get logs available fields", zap.String("searchText", searchText), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getLogsFieldValuesTool := mcp.NewTool("signoz_get_logs_field_values",
		mcp.WithDescription("Get available field values for log queries"),
		mcp.WithString("fieldName", mcp.Required(), mcp.Description("Field name to get values for (e.g., 'service.name')")),
		mcp.WithString("searchText", mcp.Description("Search text to filter values (optional)")),
	)

	s.AddTool(getLogsFieldValuesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Error("Invalid arguments type", zap.Any("arguments", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: invalid arguments format. Expected object with "fieldName" string.`), nil
		}

		fieldName, ok := args["fieldName"].(string)
		if !ok || fieldName == "" {
			h.logger.Warn("Missing or invalid fieldName", zap.Any("args", args), zap.Any("fieldName", args["fieldName"]))
			return mcp.NewToolResultError(`Parameter validation failed: "fieldName" must be a non-empty string. Examples: {"fieldName": "service.name"}, {"fieldName": "severity_text"}, {"fieldName": "body"}`), nil
		}

		searchText := ""
		if search, ok := args["searchText"].(string); ok && search != "" {
			searchText = search
		}

		h.logger.Debug("Tool called: signoz_get_logs_field_values", zap.String("fieldName", fieldName), zap.String("searchText", searchText))
		client := h.GetClient(ctx)
		result, err := client.GetLogsFieldValues(ctx, fieldName, searchText)
		if err != nil {
			h.logger.Error("Failed to get logs field values", zap.String("fieldName", fieldName), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

}

func (h *Handler) RegisterTracesHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering traces handlers")

	getTraceFieldValuesTool := mcp.NewTool("signoz_get_trace_field_values",
		mcp.WithDescription("Get available field values for trace queries"),
		mcp.WithString("fieldName", mcp.Required(), mcp.Description("Field name to get values for (e.g., 'service.name')")),
		mcp.WithString("searchText", mcp.Description("Search text to filter values (optional)")),
	)

	s.AddTool(getTraceFieldValuesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Error("Invalid arguments type", zap.Any("arguments", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: invalid arguments format. Expected object with "fieldName" string.`), nil
		}

		fieldName, ok := args["fieldName"].(string)
		if !ok || fieldName == "" {
			h.logger.Warn("Missing or invalid fieldName", zap.Any("args", args), zap.Any("fieldName", args["fieldName"]))
			return mcp.NewToolResultError(`Parameter validation failed: "fieldName" must be a non-empty string. Examples: {"fieldName": "service.name"}, {"fieldName": "http.status_code"}, {"fieldName": "operation"}`), nil
		}

		searchText := ""
		if search, ok := args["searchText"].(string); ok && search != "" {
			searchText = search
		}

		h.logger.Debug("Tool called: signoz_get_trace_field_values", zap.String("fieldName", fieldName), zap.String("searchText", searchText))
		result, err := h.client.GetTraceFieldValues(ctx, fieldName, searchText)
		if err != nil {
			h.logger.Error("Failed to get trace field values", zap.String("fieldName", fieldName), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getTraceAvailableFieldsTool := mcp.NewTool("signoz_get_trace_available_fields",
		mcp.WithDescription("Get available field names for trace queries"),
		mcp.WithString("searchText", mcp.Description("Search text to filter available fields (optional)")),
	)

	s.AddTool(getTraceAvailableFieldsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		searchText := ""
		if search, ok := args["searchText"].(string); ok && search != "" {
			searchText = search
		}

		h.logger.Debug("Tool called: signoz_get_trace_available_fields", zap.String("searchText", searchText))
		client := h.GetClient(ctx)
		result, err := client.GetTraceAvailableFields(ctx, searchText)
		if err != nil {
			h.logger.Error("Failed to get trace available fields", zap.String("searchText", searchText), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	searchTracesByServiceTool := mcp.NewTool("signoz_search_traces_by_service",
		mcp.WithDescription("Search traces for a specific service. Defaults to last 6 hours if no time specified."),
		mcp.WithString("service", mcp.Required(), mcp.Description("Service name to search traces for")),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in milliseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in milliseconds (optional, defaults to now)")),
		mcp.WithString("operation", mcp.Description("Operation name to filter by")),
		mcp.WithString("error", mcp.Description("Filter by error status (true/false)")),
		mcp.WithString("minDuration", mcp.Description("Minimum duration in nanoseconds")),
		mcp.WithString("maxDuration", mcp.Description("Maximum duration in nanoseconds")),
		mcp.WithString("limit", mcp.Description("Maximum number of traces to return (default: 100)")),
	)

	s.AddTool(searchTracesByServiceTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		service, ok := args["service"].(string)
		if !ok || service == "" {
			return mcp.NewToolResultError(`Parameter validation failed: "service" must be a non-empty string. Example: {"service": "frontend-api", "timeRange": "2h", "error": "true", "limit": "100"}`), nil
		}

		start, end := timeutil.GetTimestampsWithDefaults(args, "ms")

		limit := 100
		if limitStr, ok := args["limit"].(string); ok && limitStr != "" {
			if limitInt, err := strconv.Atoi(limitStr); err == nil {
				limit = limitInt
			}
		}

		filterExpression := fmt.Sprintf("service.name in ['%s']", service)

		if operation, ok := args["operation"].(string); ok && operation != "" {
			filterExpression += fmt.Sprintf(" AND name = '%s'", operation)
		}

		if errorFilter, ok := args["error"].(string); ok && errorFilter != "" {
			switch errorFilter {
			case "true":
				filterExpression += " AND hasError = true"
			case "false":
				filterExpression += " AND hasError = false"
			}
		}

		if minDuration, ok := args["minDuration"].(string); ok && minDuration != "" {
			filterExpression += fmt.Sprintf(" AND durationNano >= %s", minDuration)
		}

		if maxDuration, ok := args["maxDuration"].(string); ok && maxDuration != "" {
			filterExpression += fmt.Sprintf(" AND durationNano <= %s", maxDuration)
		}

		var startTime, endTime int64
		if err := json.Unmarshal([]byte(start), &startTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "start" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, start)), nil
		}
		if err := json.Unmarshal([]byte(end), &endTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "end" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, end)), nil
		}

		queryPayload := types.BuildTracesQueryPayload(startTime, endTime, filterExpression, limit)

		queryJSON, err := json.Marshal(queryPayload)
		if err != nil {
			h.logger.Error("Failed to marshal query payload", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal query payload: " + err.Error()), nil
		}

		h.logger.Debug("Tool called: signoz_search_traces_by_service", zap.String("service", service), zap.String("start", start), zap.String("end", end))
		result, err := h.client.QueryBuilderV5(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to search traces by service", zap.String("service", service), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	getTraceDetailsTool := mcp.NewTool("signoz_get_trace_details",
		mcp.WithDescription("Get comprehensive trace information including all spans and metadata. Defaults to last 6 hours if no time specified."),
		mcp.WithString("traceId", mcp.Required(), mcp.Description("Trace ID to get details for")),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in milliseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in milliseconds (optional, defaults to now)")),
		mcp.WithString("includeSpans", mcp.Description("Include detailed span information (true/false, default: true)")),
	)

	s.AddTool(getTraceDetailsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		traceID, ok := args["traceId"].(string)
		if !ok || traceID == "" {
			return mcp.NewToolResultError(`Parameter validation failed: "traceId" must be a non-empty string. Example: {"traceId": "abc123def456", "includeSpans": "true", "timeRange": "1h"}`), nil
		}

		start, end := timeutil.GetTimestampsWithDefaults(args, "ms")

		includeSpans := true
		if includeStr, ok := args["includeSpans"].(string); ok && includeStr != "" {
			includeSpans = includeStr == "true"
		}

		var startTime, endTime int64
		if err := json.Unmarshal([]byte(start), &startTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "start" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, start)), nil
		}
		if err := json.Unmarshal([]byte(end), &endTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "end" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, end)), nil
		}

		h.logger.Debug("Tool called: signoz_get_trace_details", zap.String("traceId", traceID), zap.Bool("includeSpans", includeSpans), zap.String("start", start), zap.String("end", end))
		result, err := h.client.GetTraceDetails(ctx, traceID, includeSpans, startTime, endTime)
		if err != nil {
			h.logger.Error("Failed to get trace details", zap.String("traceId", traceID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getTraceErrorAnalysisTool := mcp.NewTool("signoz_get_trace_error_analysis",
		mcp.WithDescription("Analyze error patterns in traces. Defaults to last 6 hours if no time specified."),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in milliseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in milliseconds (optional, defaults to now)")),
		mcp.WithString("service", mcp.Description("Service name to filter by (optional)")),
	)

	s.AddTool(getTraceErrorAnalysisTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		start, end := timeutil.GetTimestampsWithDefaults(args, "ms")

		service := ""
		if s, ok := args["service"].(string); ok && s != "" {
			service = s
		}

		var startTime, endTime int64
		if err := json.Unmarshal([]byte(start), &startTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "start" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, start)), nil
		}
		if err := json.Unmarshal([]byte(end), &endTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "end" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, end)), nil
		}

		h.logger.Debug("Tool called: signoz_get_trace_error_analysis", zap.String("start", start), zap.String("end", end), zap.String("service", service))
		result, err := h.client.GetTraceErrorAnalysis(ctx, startTime, endTime, service)
		if err != nil {
			h.logger.Error("Failed to get trace error analysis", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getTraceSpanHierarchyTool := mcp.NewTool("signoz_get_trace_span_hierarchy",
		mcp.WithDescription("Get trace span relationships and hierarchy. Defaults to last 6 hours if no time specified."),
		mcp.WithString("traceId", mcp.Required(), mcp.Description("Trace ID to get span hierarchy for")),
		mcp.WithString("timeRange", mcp.Description("Time range string (optional, overrides start/end). Format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). Examples: '30m', '1h', '2h', '6h', '24h', '7d'. Defaults to last 6 hours if not provided.")),
		mcp.WithString("start", mcp.Description("Start time in milliseconds (optional, defaults to 6 hours ago)")),
		mcp.WithString("end", mcp.Description("End time in milliseconds (optional, defaults to now)")),
	)

	s.AddTool(getTraceSpanHierarchyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.Params.Arguments.(map[string]any)

		traceID, ok := args["traceId"].(string)
		if !ok || traceID == "" {
			return mcp.NewToolResultError(`Parameter validation failed: "traceId" must be a non-empty string. Example: {"traceId": "abc123def456", "timeRange": "1h"}`), nil
		}

		start, end := timeutil.GetTimestampsWithDefaults(args, "ms")

		var startTime, endTime int64
		if err := json.Unmarshal([]byte(start), &startTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "start" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, start)), nil
		}
		if err := json.Unmarshal([]byte(end), &endTime); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf(`Internal error: Invalid "end" timestamp format: %s. Use "timeRange" parameter instead (e.g., "1h", "24h")`, end)), nil
		}

		h.logger.Debug("Tool called: signoz_get_trace_span_hierarchy", zap.String("traceId", traceID), zap.String("start", start), zap.String("end", end))
		result, err := h.client.GetTraceSpanHierarchy(ctx, traceID, startTime, endTime)
		if err != nil {
			h.logger.Error("Failed to get trace span hierarchy", zap.String("traceId", traceID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

}

func (h *Handler) RegisterSavedViewHandlers(s *server.MCPServer) {
	createSavedViewTool := mcp.NewTool(
		"signoz_create_saved_view",
		mcp.WithDescription(
			"Create a new saved view for logs or traces explorer. Saved views store filter/query configurations for quick reuse. "+
				"Use signoz_get_log_view on an existing view to understand the compositeQuery structure before creating a new one.",
		),
		mcp.WithInputSchema[types.SavedView](),
	)

	s.AddTool(createSavedViewTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rawConfig, ok := req.Params.Arguments.(map[string]any)

		if !ok || len(rawConfig) == 0 {
			h.logger.Warn("Received empty or invalid arguments map.")
			return mcp.NewToolResultError(`Parameter validation failed: The saved view configuration object is empty or improperly formatted.`), nil
		}

		configJSON, err := json.Marshal(rawConfig)
		if err != nil {
			h.logger.Error("Failed to unmarshal raw configuration", zap.Error(err))
			return mcp.NewToolResultError(
				fmt.Sprintf("Could not decode raw configuration. Error: %s", err.Error()),
			), nil
		}

		var savedViewConfig types.SavedView
		if err := json.Unmarshal(configJSON, &savedViewConfig); err != nil {
			return mcp.NewToolResultError(
				fmt.Sprintf("Parameter decoding error: The provided JSON structure for the saved view configuration is invalid. Error details: %s", err.Error()),
			), nil
		}

		h.logger.Debug("Tool called: signoz_create_saved_view", zap.String("name", savedViewConfig.Name))
		client := h.GetClient(ctx)
		data, err := client.CreateSavedView(ctx, savedViewConfig)

		if err != nil {
			h.logger.Error("Failed to create saved view in SigNoz", zap.Error(err))
			return mcp.NewToolResultError(fmt.Sprintf("SigNoz API Error: %s", err.Error())), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	})

	updateSavedViewTool := mcp.NewTool(
		"signoz_update_saved_view",
		mcp.WithDescription(
			"Update an existing saved view. Requires the complete post-update configuration. "+
				"Use signoz_get_log_view to retrieve the current configuration first.",
		),
		mcp.WithInputSchema[types.UpdateSavedViewInput](),
	)

	s.AddTool(updateSavedViewTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rawConfig, ok := req.Params.Arguments.(map[string]any)

		if !ok || len(rawConfig) == 0 {
			h.logger.Warn("Received empty or invalid arguments map.")
			return mcp.NewToolResultError(`Parameter validation failed: The saved view configuration object is empty or improperly formatted.`), nil
		}

		configJSON, err := json.Marshal(rawConfig)
		if err != nil {
			h.logger.Error("Failed to unmarshal raw configuration", zap.Error(err))
			return mcp.NewToolResultError(
				fmt.Sprintf("Could not decode raw configuration. Error: %s", err.Error()),
			), nil
		}

		var updateSavedViewConfig types.UpdateSavedViewInput
		if err := json.Unmarshal(configJSON, &updateSavedViewConfig); err != nil {
			return mcp.NewToolResultError(
				fmt.Sprintf("Parameter decoding error: The provided JSON structure for the saved view configuration is invalid. Error details: %s", err.Error()),
			), nil
		}

		if updateSavedViewConfig.ViewID == "" {
			h.logger.Warn("Empty viewId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "viewId" cannot be empty. Provide a valid saved view ID. Use signoz_list_log_views tool to see available views.`), nil
		}

		h.logger.Debug("Tool called: signoz_update_saved_view", zap.String("viewId", updateSavedViewConfig.ViewID))
		client := h.GetClient(ctx)
		data, err := client.UpdateSavedView(ctx, updateSavedViewConfig.ViewID, updateSavedViewConfig.SavedView)

		if err != nil {
			h.logger.Error("Failed to update saved view in SigNoz", zap.Error(err))
			return mcp.NewToolResultError(fmt.Sprintf("SigNoz API Error: %s", err.Error())), nil
		}

		return mcp.NewToolResultText(string(data)), nil
	})

	deleteSavedViewTool := mcp.NewTool("signoz_delete_saved_view",
		mcp.WithDescription("Delete a saved view by ID. This action is irreversible. Use signoz_list_log_views to find view IDs."),
		mcp.WithString("viewId", mcp.Required(), mcp.Description("Saved view ID to delete")),
	)

	s.AddTool(deleteSavedViewTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		viewID, ok := req.Params.Arguments.(map[string]any)["viewId"].(string)
		if !ok {
			h.logger.Warn("Invalid viewId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "viewId" must be a string. Example: {"viewId": "view-uuid-123"}`), nil
		}
		if viewID == "" {
			h.logger.Warn("Empty viewId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "viewId" cannot be empty. Provide a valid saved view ID. Use signoz_list_log_views tool to see available views.`), nil
		}

		h.logger.Debug("Tool called: signoz_delete_saved_view", zap.String("viewId", viewID))
		client := h.GetClient(ctx)
		err := client.DeleteSavedView(ctx, viewID)
		if err != nil {
			h.logger.Error("Failed to delete saved view", zap.String("viewId", viewID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("saved view deleted"), nil
	})
}

func (h *Handler) RegisterNotificationChannelHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering notification channel handlers")

	listChannelsTool := mcp.NewTool("signoz_list_notification_channels",
		mcp.WithDescription("List all notification channels configured in SigNoz. Returns channel names, types (slack, email, pagerduty, webhook, msteams, opsgenie, telegram, etc.), and IDs. IMPORTANT: This tool supports pagination using 'limit' and 'offset' parameters. The response includes 'pagination' metadata with 'total', 'hasMore', and 'nextOffset' fields. When searching for a specific channel, ALWAYS check 'pagination.hasMore' - if true, continue paginating through all pages using 'nextOffset' until you find the item or 'hasMore' is false. Never conclude an item doesn't exist until you've checked all pages. Default: limit=50, offset=0."),
		mcp.WithString("limit", mcp.Description("Maximum number of channels to return per page. Use this to paginate through large result sets. Default: 50. Example: '50' for 50 results, '100' for 100 results. Must be greater than 0.")),
		mcp.WithString("offset", mcp.Description("Number of results to skip before returning results. Use for pagination: offset=0 for first page, offset=50 for second page (if limit=50), offset=100 for third page, etc. Check 'pagination.nextOffset' in the response to get the next page offset. Default: 0. Must be >= 0.")),
	)

	s.AddTool(listChannelsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_notification_channels")
		limit, offset := paginate.ParseParams(req.Params.Arguments)

		client := h.GetClient(ctx)
		result, err := client.ListNotificationChannels(ctx)
		if err != nil {
			h.logger.Error("Failed to list notification channels", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		var channels map[string]any
		if err := json.Unmarshal(result, &channels); err != nil {
			h.logger.Error("Failed to parse notification channels response", zap.Error(err))
			return mcp.NewToolResultError("failed to parse response: " + err.Error()), nil
		}

		data, ok := channels["data"].([]any)
		if !ok {
			h.logger.Error("Invalid notification channels response format", zap.Any("data", channels["data"]))
			return mcp.NewToolResultError("invalid response format: expected data array"), nil
		}

		total := len(data)
		pagedData := paginate.Array(data, offset, limit)

		resultJSON, err := paginate.Wrap(pagedData, total, offset, limit)
		if err != nil {
			h.logger.Error("Failed to wrap notification channels with pagination", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal response: " + err.Error()), nil
		}

		return mcp.NewToolResultText(string(resultJSON)), nil
	})

	getChannelTool := mcp.NewTool("signoz_get_notification_channel",
		mcp.WithDescription("Get details of a specific notification channel by ID. Returns the full channel configuration including the receiver settings."),
		mcp.WithString("channelId", mcp.Required(), mcp.Description("Notification channel ID")),
	)

	s.AddTool(getChannelTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		channelID, ok := req.Params.Arguments.(map[string]any)["channelId"].(string)
		if !ok {
			h.logger.Warn("Invalid channelId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "channelId" must be a string. Example: {"channelId": "channel-uuid-123"}`), nil
		}
		if channelID == "" {
			h.logger.Warn("Empty channelId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "channelId" cannot be empty. Provide a valid notification channel ID. Use signoz_list_notification_channels tool to see available channels.`), nil
		}

		h.logger.Debug("Tool called: signoz_get_notification_channel", zap.String("channelId", channelID))
		client := h.GetClient(ctx)
		data, err := client.GetNotificationChannel(ctx, channelID)
		if err != nil {
			h.logger.Error("Failed to get notification channel", zap.String("channelId", channelID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	})

	createChannelTool := mcp.NewTool("signoz_create_notification_channel",
		mcp.WithDescription(`Create a new notification channel. The receiver parameter must be a complete Prometheus Alertmanager Receiver JSON object. Required fields: name (string), plus one or more config arrays for the channel type. Supported types: slack_configs, email_configs, pagerduty_configs, webhook_configs, opsgenie_configs, msteams_configs, telegram_configs, etc. Example for Slack: {"name": "my-slack", "slack_configs": [{"api_url": "https://hooks.slack.com/...", "channel": "#alerts"}]}`),
		mcp.WithObject("receiver", mcp.Required(), mcp.Description("Complete Prometheus Alertmanager Receiver JSON object")),
	)

	s.AddTool(createChannelTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_notification_channel")

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Warn("Invalid arguments payload type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}

		receiverObj, ok := args["receiver"].(map[string]any)
		if !ok {
			h.logger.Warn("Invalid receiver parameter type", zap.Any("type", args["receiver"]))
			return mcp.NewToolResultError("receiver parameter must be a JSON object"), nil
		}

		receiverJSON, err := json.Marshal(receiverObj)
		if err != nil {
			h.logger.Error("Failed to marshal receiver object", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal receiver object: " + err.Error()), nil
		}

		client := h.GetClient(ctx)
		result, err := client.CreateNotificationChannel(ctx, receiverJSON)
		if err != nil {
			h.logger.Error("Failed to create notification channel", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	updateChannelTool := mcp.NewTool("signoz_update_notification_channel",
		mcp.WithDescription("Update an existing notification channel. IMPORTANT: The channel name cannot be changed during update. Use signoz_get_notification_channel to retrieve the current config first."),
		mcp.WithString("channelId", mcp.Required(), mcp.Description("Notification channel ID to update")),
		mcp.WithObject("receiver", mcp.Required(), mcp.Description("Complete Prometheus Alertmanager Receiver JSON object representing the post-update state")),
	)

	s.AddTool(updateChannelTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_notification_channel")

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Warn("Invalid arguments payload type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}

		channelID, ok := args["channelId"].(string)
		if !ok {
			h.logger.Warn("Invalid channelId parameter type", zap.Any("type", args["channelId"]))
			return mcp.NewToolResultError(`Parameter validation failed: "channelId" must be a string. Example: {"channelId": "channel-uuid-123"}`), nil
		}
		if channelID == "" {
			h.logger.Warn("Empty channelId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "channelId" cannot be empty. Provide a valid notification channel ID`), nil
		}

		receiverObj, ok := args["receiver"].(map[string]any)
		if !ok {
			h.logger.Warn("Invalid receiver parameter type", zap.Any("type", args["receiver"]))
			return mcp.NewToolResultError("receiver parameter must be a JSON object"), nil
		}

		receiverJSON, err := json.Marshal(receiverObj)
		if err != nil {
			h.logger.Error("Failed to marshal receiver object", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal receiver object: " + err.Error()), nil
		}

		client := h.GetClient(ctx)
		err = client.UpdateNotificationChannel(ctx, channelID, receiverJSON)
		if err != nil {
			h.logger.Error("Failed to update notification channel", zap.String("channelId", channelID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText("notification channel updated"), nil
	})

	deleteChannelTool := mcp.NewTool("signoz_delete_notification_channel",
		mcp.WithDescription("Delete a notification channel by ID. This action is irreversible. Use signoz_list_notification_channels to find channel IDs."),
		mcp.WithString("channelId", mcp.Required(), mcp.Description("Notification channel ID to delete")),
	)

	s.AddTool(deleteChannelTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		channelID, ok := req.Params.Arguments.(map[string]any)["channelId"].(string)
		if !ok {
			h.logger.Warn("Invalid channelId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "channelId" must be a string. Example: {"channelId": "channel-uuid-123"}`), nil
		}
		if channelID == "" {
			h.logger.Warn("Empty channelId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "channelId" cannot be empty. Provide a valid notification channel ID. Use signoz_list_notification_channels to find channel IDs.`), nil
		}

		h.logger.Debug("Tool called: signoz_delete_notification_channel", zap.String("channelId", channelID))
		client := h.GetClient(ctx)
		err := client.DeleteNotificationChannel(ctx, channelID)
		if err != nil {
			h.logger.Error("Failed to delete notification channel", zap.String("channelId", channelID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText("notification channel deleted"), nil
	})
}

func (h *Handler) RegisterDowntimeScheduleHandlers(s *server.MCPServer) {
	h.logger.Debug("Registering downtime schedule handlers")

	listSchedulesTool := mcp.NewTool("signoz_list_downtime_schedules",
		mcp.WithDescription("List all downtime schedules (maintenance windows) in SigNoz. Downtime schedules mute alerts during planned maintenance. Returns schedule names, types (fixed/recurring), status (active/upcoming/expired), and associated alert IDs."),
		mcp.WithString("active", mcp.Description("Filter by active status: 'true' for active schedules, 'false' for inactive")),
	)

	s.AddTool(listSchedulesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_downtime_schedules")

		client := h.GetClient(ctx)
		result, err := client.ListDowntimeSchedules(ctx)
		if err != nil {
			h.logger.Error("Failed to list downtime schedules", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	getScheduleTool := mcp.NewTool("signoz_get_downtime_schedule",
		mcp.WithDescription("Get details of a specific downtime schedule by ID, including the full schedule configuration (timezone, times, recurrence settings)."),
		mcp.WithString("scheduleId", mcp.Required(), mcp.Description("Downtime schedule ID")),
	)

	s.AddTool(getScheduleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scheduleID, ok := req.Params.Arguments.(map[string]any)["scheduleId"].(string)
		if !ok {
			h.logger.Warn("Invalid scheduleId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "scheduleId" must be a string. Example: {"scheduleId": "schedule-uuid-123"}`), nil
		}
		if scheduleID == "" {
			h.logger.Warn("Empty scheduleId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "scheduleId" cannot be empty. Provide a valid downtime schedule ID. Use signoz_list_downtime_schedules to find schedule IDs.`), nil
		}

		h.logger.Debug("Tool called: signoz_get_downtime_schedule", zap.String("scheduleId", scheduleID))
		client := h.GetClient(ctx)
		result, err := client.GetDowntimeSchedule(ctx, scheduleID)
		if err != nil {
			h.logger.Error("Failed to get downtime schedule", zap.String("scheduleId", scheduleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	createScheduleTool := mcp.NewTool("signoz_create_downtime_schedule",
		mcp.WithDescription("Create a new downtime schedule to mute alerts during maintenance. The schedule object must include: name (string), alertIds (array of alert rule IDs to mute, or empty array for all alerts), schedule (object with timezone, and either startTime+endTime for fixed schedules, or recurrence object with startTime, duration, repeatType (daily/weekly/monthly), and repeatOn array for weekly). Example fixed: {\"name\": \"DB Migration\", \"alertIds\": [], \"schedule\": {\"timezone\": \"UTC\", \"startTime\": \"2026-02-15T02:00:00Z\", \"endTime\": \"2026-02-15T04:00:00Z\"}}. Example recurring: {\"name\": \"Weekly Window\", \"alertIds\": [], \"schedule\": {\"timezone\": \"UTC\", \"recurrence\": {\"startTime\": \"2026-02-01T22:00:00Z\", \"duration\": \"2h\", \"repeatType\": \"weekly\", \"repeatOn\": [\"tuesday\", \"thursday\"]}}}."),
		mcp.WithObject("schedule", mcp.Required(), mcp.Description("Complete downtime schedule JSON object")),
	)

	s.AddTool(createScheduleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_downtime_schedule")

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Warn("Invalid arguments payload type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}

		scheduleObj, ok := args["schedule"].(map[string]any)
		if !ok {
			h.logger.Warn("Invalid schedule parameter type", zap.Any("type", args["schedule"]))
			return mcp.NewToolResultError("schedule parameter must be a JSON object"), nil
		}

		scheduleJSON, err := json.Marshal(scheduleObj)
		if err != nil {
			h.logger.Error("Failed to marshal schedule object", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal schedule object: " + err.Error()), nil
		}

		client := h.GetClient(ctx)
		result, err := client.CreateDowntimeSchedule(ctx, scheduleJSON)
		if err != nil {
			h.logger.Error("Failed to create downtime schedule", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(string(result)), nil
	})

	updateScheduleTool := mcp.NewTool("signoz_update_downtime_schedule",
		mcp.WithDescription("Update an existing downtime schedule. Use signoz_get_downtime_schedule to retrieve current config first."),
		mcp.WithString("scheduleId", mcp.Required(), mcp.Description("Downtime schedule ID to update")),
		mcp.WithObject("schedule", mcp.Required(), mcp.Description("Complete downtime schedule JSON object representing the post-update state")),
	)

	s.AddTool(updateScheduleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_downtime_schedule")

		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			h.logger.Warn("Invalid arguments payload type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}

		scheduleID, ok := args["scheduleId"].(string)
		if !ok {
			h.logger.Warn("Invalid scheduleId parameter type", zap.Any("type", args["scheduleId"]))
			return mcp.NewToolResultError(`Parameter validation failed: "scheduleId" must be a string`), nil
		}
		if scheduleID == "" {
			h.logger.Warn("Empty scheduleId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "scheduleId" cannot be empty. Provide a valid downtime schedule ID.`), nil
		}

		scheduleObj, ok := args["schedule"].(map[string]any)
		if !ok {
			h.logger.Warn("Invalid schedule parameter type", zap.Any("type", args["schedule"]))
			return mcp.NewToolResultError("schedule parameter must be a JSON object"), nil
		}

		scheduleJSON, err := json.Marshal(scheduleObj)
		if err != nil {
			h.logger.Error("Failed to marshal schedule object", zap.Error(err))
			return mcp.NewToolResultError("failed to marshal schedule object: " + err.Error()), nil
		}

		client := h.GetClient(ctx)
		err = client.UpdateDowntimeSchedule(ctx, scheduleID, scheduleJSON)
		if err != nil {
			h.logger.Error("Failed to update downtime schedule", zap.String("scheduleId", scheduleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText("downtime schedule updated"), nil
	})

	deleteScheduleTool := mcp.NewTool("signoz_delete_downtime_schedule",
		mcp.WithDescription("Delete a downtime schedule by ID. This action is irreversible."),
		mcp.WithString("scheduleId", mcp.Required(), mcp.Description("Downtime schedule ID to delete")),
	)

	s.AddTool(deleteScheduleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scheduleID, ok := req.Params.Arguments.(map[string]any)["scheduleId"].(string)
		if !ok {
			h.logger.Warn("Invalid scheduleId parameter type", zap.Any("type", req.Params.Arguments))
			return mcp.NewToolResultError(`Parameter validation failed: "scheduleId" must be a string. Example: {"scheduleId": "schedule-uuid-123"}`), nil
		}
		if scheduleID == "" {
			h.logger.Warn("Empty scheduleId parameter")
			return mcp.NewToolResultError(`Parameter validation failed: "scheduleId" cannot be empty. Provide a valid downtime schedule ID. Use signoz_list_downtime_schedules to find schedule IDs.`), nil
		}

		h.logger.Debug("Tool called: signoz_delete_downtime_schedule", zap.String("scheduleId", scheduleID))
		client := h.GetClient(ctx)
		err := client.DeleteDowntimeSchedule(ctx, scheduleID)
		if err != nil {
			h.logger.Error("Failed to delete downtime schedule", zap.String("scheduleId", scheduleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText("downtime schedule deleted"), nil
	})
}

func (h *Handler) RegisterRoutePolicyHandlers(s *server.MCPServer) {
	listPoliciesTool := mcp.NewTool("signoz_list_route_policies",
		mcp.WithDescription("List all alert route policies. Route policies control how alerts are routed to notification channels based on matching expressions."),
	)

	s.AddTool(listPoliciesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_route_policies")
		client := h.GetClient(ctx)
		result, err := client.ListRoutePolicies(ctx)
		if err != nil {
			h.logger.Error("Failed to list route policies", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getPoliciesTool := mcp.NewTool("signoz_get_route_policy",
		mcp.WithDescription("Get details of a specific alert route policy by ID."),
		mcp.WithString("policyId", mcp.Required(), mcp.Description("Route policy ID")),
	)

	s.AddTool(getPoliciesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_route_policy")
		policyID, ok := req.Params.Arguments.(map[string]any)["policyId"].(string)
		if !ok || policyID == "" {
			return mcp.NewToolResultError("policyId is required and must be a non-empty string"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetRoutePolicy(ctx, policyID)
		if err != nil {
			h.logger.Error("Failed to get route policy", zap.String("policyId", policyID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	createPolicyTool := mcp.NewTool("signoz_create_route_policy",
		mcp.WithDescription("Create a new alert route policy. Route policies use expr-lang expressions to match alerts and route them to specific notification channels. Fields: name (string), expression (expr-lang string e.g. 'severity == \"critical\"'), channels (array of channel IDs), description (optional string), tags (optional array)."),
		mcp.WithObject("policy", mcp.Required(), mcp.Description("Route policy JSON object with name, expression, channels, and optional description/tags")),
	)

	s.AddTool(createPolicyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_route_policy")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		policyObj, ok := args["policy"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("policy parameter must be a JSON object"), nil
		}
		policyJSON, err := json.Marshal(policyObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal policy: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.CreateRoutePolicy(ctx, policyJSON)
		if err != nil {
			h.logger.Error("Failed to create route policy", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	updatePolicyTool := mcp.NewTool("signoz_update_route_policy",
		mcp.WithDescription("Update an existing alert route policy. Use signoz_get_route_policy to retrieve current config first."),
		mcp.WithString("policyId", mcp.Required(), mcp.Description("Route policy ID to update")),
		mcp.WithObject("policy", mcp.Required(), mcp.Description("Complete route policy JSON object representing the post-update state")),
	)

	s.AddTool(updatePolicyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_route_policy")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		policyID, ok := args["policyId"].(string)
		if !ok || policyID == "" {
			return mcp.NewToolResultError("policyId is required and must be a non-empty string"), nil
		}
		policyObj, ok := args["policy"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("policy parameter must be a JSON object"), nil
		}
		policyJSON, err := json.Marshal(policyObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal policy: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		err = client.UpdateRoutePolicy(ctx, policyID, policyJSON)
		if err != nil {
			h.logger.Error("Failed to update route policy", zap.String("policyId", policyID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("route policy updated"), nil
	})

	deletePolicyTool := mcp.NewTool("signoz_delete_route_policy",
		mcp.WithDescription("Delete an alert route policy by ID. This action is irreversible."),
		mcp.WithString("policyId", mcp.Required(), mcp.Description("Route policy ID to delete")),
	)

	s.AddTool(deletePolicyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		policyID, ok := req.Params.Arguments.(map[string]any)["policyId"].(string)
		if !ok || policyID == "" {
			return mcp.NewToolResultError("policyId is required and must be a non-empty string"), nil
		}
		h.logger.Debug("Tool called: signoz_delete_route_policy", zap.String("policyId", policyID))
		client := h.GetClient(ctx)
		err := client.DeleteRoutePolicy(ctx, policyID)
		if err != nil {
			h.logger.Error("Failed to delete route policy", zap.String("policyId", policyID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("route policy deleted"), nil
	})
}

func (h *Handler) RegisterDependencyGraphHandlers(s *server.MCPServer) {
	depGraphTool := mcp.NewTool("signoz_get_dependency_graph",
		mcp.WithDescription("Get the service dependency graph showing relationships between services. Requires start and end timestamps as string nanoseconds, and optional tags for filtering."),
		mcp.WithObject("query", mcp.Required(), mcp.Description("Query object with 'start' (string nanosecond timestamp), 'end' (string nanosecond timestamp), and optional 'tags' array")),
	)

	s.AddTool(depGraphTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_dependency_graph")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		queryObj, ok := args["query"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("query parameter must be a JSON object with start and end timestamps"), nil
		}
		for _, key := range []string{"start", "end"} {
			if v, exists := queryObj[key]; exists {
				if num, isNum := v.(float64); isNum {
					queryObj[key] = fmt.Sprintf("%.0f", num)
				}
			}
		}
		queryJSON, err := json.Marshal(queryObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal query: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetDependencyGraph(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to get dependency graph", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterTTLSettingsHandlers(s *server.MCPServer) {
	getTTLTool := mcp.NewTool("signoz_get_ttl_settings",
		mcp.WithDescription("Get current data retention (TTL) settings. Fetches all signal types (metrics, traces, logs) and returns combined results."),
	)

	s.AddTool(getTTLTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_ttl_settings")
		client := h.GetClient(ctx)
		types := []string{"metrics", "traces", "logs"}
		combined := make(map[string]json.RawMessage)
		for _, t := range types {
			result, err := client.GetTTLSettings(ctx, t)
			if err != nil {
				h.logger.Error("Failed to get TTL settings", zap.String("type", t), zap.Error(err))
				return mcp.NewToolResultError("failed to get TTL for " + t + ": " + err.Error()), nil
			}
			combined[t] = result
		}
		out, err := json.Marshal(combined)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal combined TTL: " + err.Error()), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	})

	setTTLTool := mcp.NewTool("signoz_set_ttl_settings",
		mcp.WithDescription("Set data retention (TTL) for a specific signal type. Duration format examples: '720h' (30 days), '2160h' (90 days)."),
		mcp.WithString("type", mcp.Required(), mcp.Description("Signal type: 'metrics', 'traces', or 'logs'")),
		mcp.WithString("duration", mcp.Required(), mcp.Description("Retention duration in Go duration format, e.g. '720h' for 30 days")),
	)

	s.AddTool(setTTLTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_set_ttl_settings")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		signalType, ok := args["type"].(string)
		if !ok || signalType == "" {
			return mcp.NewToolResultError("type is required (metrics, traces, or logs)"), nil
		}
		duration, ok := args["duration"].(string)
		if !ok || duration == "" {
			return mcp.NewToolResultError("duration is required (e.g. '720h')"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.SetTTLSettings(ctx, signalType, duration)
		if err != nil {
			h.logger.Error("Failed to set TTL settings", zap.String("type", signalType), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getTTLV2Tool := mcp.NewTool("signoz_get_ttl_settings_v2",
		mcp.WithDescription("Get data retention (TTL) settings using V2 API with support for custom retention rules per signal type."),
	)

	s.AddTool(getTTLV2Tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_ttl_settings_v2")
		client := h.GetClient(ctx)
		result, err := client.GetTTLSettingsV2(ctx)
		if err != nil {
			h.logger.Error("Failed to get TTL settings V2", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	setTTLV2Tool := mcp.NewTool("signoz_set_ttl_settings_v2",
		mcp.WithDescription("Set data retention (TTL) using V2 API with custom retention rules. Supports per-signal-type configuration with cold storage settings."),
		mcp.WithObject("settings", mcp.Required(), mcp.Description("TTL settings V2 JSON object with custom retention rules")),
	)

	s.AddTool(setTTLV2Tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_set_ttl_settings_v2")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		settingsObj, ok := args["settings"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("settings parameter must be a JSON object"), nil
		}
		settingsJSON, err := json.Marshal(settingsObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal settings: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.SetTTLSettingsV2(ctx, settingsJSON)
		if err != nil {
			h.logger.Error("Failed to set TTL settings V2", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterInfraMetricsHandlers(s *server.MCPServer) {
	listInfraTool := mcp.NewTool("signoz_list_infra_resources",
		mcp.WithDescription("List infrastructure resources of a given type. Supported types: hosts, processes, pods, pvcs, nodes, namespaces, clusters, deployments, daemonsets, statefulsets, jobs. The query body should include filters, groupBy, orderBy, offset, limit fields."),
		mcp.WithString("resourceType", mcp.Required(), mcp.Description("Resource type: hosts, processes, pods, pvcs, nodes, namespaces, clusters, deployments, daemonsets, statefulsets, or jobs")),
		mcp.WithObject("query", mcp.Required(), mcp.Description("Query object with filters, groupBy, orderBy, offset, limit")),
	)

	s.AddTool(listInfraTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_infra_resources")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		resourceType, ok := args["resourceType"].(string)
		if !ok || resourceType == "" {
			return mcp.NewToolResultError("resourceType is required"), nil
		}
		queryObj, ok := args["query"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("query parameter must be a JSON object"), nil
		}
		queryJSON, err := json.Marshal(queryObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal query: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.ListInfraResources(ctx, resourceType, queryJSON)
		if err != nil {
			h.logger.Error("Failed to list infra resources", zap.String("resourceType", resourceType), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	attrKeysTool := mcp.NewTool("signoz_get_infra_attribute_keys",
		mcp.WithDescription("Get available attribute keys for an infrastructure resource type. Use this to discover filterable/groupable attributes. Supported types: hosts, processes, pods, pvcs, nodes, namespaces, clusters, deployments, daemonsets, statefulsets, jobs."),
		mcp.WithString("resourceType", mcp.Required(), mcp.Description("Resource type: hosts, processes, pods, pvcs, nodes, namespaces, clusters, deployments, daemonsets, statefulsets, or jobs")),
	)

	s.AddTool(attrKeysTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_infra_attribute_keys")
		resourceType, ok := req.Params.Arguments.(map[string]any)["resourceType"].(string)
		if !ok || resourceType == "" {
			return mcp.NewToolResultError("resourceType is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetInfraAttributeKeys(ctx, resourceType)
		if err != nil {
			h.logger.Error("Failed to get infra attribute keys", zap.String("resourceType", resourceType), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	attrValuesTool := mcp.NewTool("signoz_get_infra_attribute_values",
		mcp.WithDescription("Get available attribute values for an infrastructure resource type. Use this to discover possible values for filtering. Supported types: hosts, processes, pods, pvcs, nodes, namespaces, clusters, deployments, daemonsets, statefulsets, jobs."),
		mcp.WithString("resourceType", mcp.Required(), mcp.Description("Resource type: hosts, processes, pods, pvcs, nodes, namespaces, clusters, deployments, daemonsets, statefulsets, or jobs")),
	)

	s.AddTool(attrValuesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_infra_attribute_values")
		resourceType, ok := req.Params.Arguments.(map[string]any)["resourceType"].(string)
		if !ok || resourceType == "" {
			return mcp.NewToolResultError("resourceType is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetInfraAttributeValues(ctx, resourceType)
		if err != nil {
			h.logger.Error("Failed to get infra attribute values", zap.String("resourceType", resourceType), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterLogsPipelinesHandlers(s *server.MCPServer) {
	getPipelinesTool := mcp.NewTool("signoz_get_logs_pipelines",
		mcp.WithDescription("Get logs processing pipelines configuration. Returns pipeline definitions including processors, filters, and routing rules."),
		mcp.WithString("version", mcp.Required(), mcp.Description("Pipeline config version to retrieve (e.g. 'latest' or a specific version number)")),
	)

	s.AddTool(getPipelinesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_logs_pipelines")
		version, ok := req.Params.Arguments.(map[string]any)["version"].(string)
		if !ok || version == "" {
			return mcp.NewToolResultError("version is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetLogsPipelines(ctx, version)
		if err != nil {
			h.logger.Error("Failed to get logs pipelines", zap.String("version", version), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	savePipelinesTool := mcp.NewTool("signoz_save_logs_pipelines",
		mcp.WithDescription("Save/update logs processing pipelines configuration. Replaces the entire pipeline config."),
		mcp.WithObject("pipelines", mcp.Required(), mcp.Description("Complete pipelines configuration JSON object")),
	)

	s.AddTool(savePipelinesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_save_logs_pipelines")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		pipelinesObj, ok := args["pipelines"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("pipelines parameter must be a JSON object"), nil
		}
		pipelinesJSON, err := json.Marshal(pipelinesObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal pipelines: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.SaveLogsPipelines(ctx, pipelinesJSON)
		if err != nil {
			h.logger.Error("Failed to save logs pipelines", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	previewPipelineTool := mcp.NewTool("signoz_preview_logs_pipeline",
		mcp.WithDescription("Preview the effect of a logs pipeline on sample log data without saving. Useful for testing pipeline transformations."),
		mcp.WithObject("preview", mcp.Required(), mcp.Description("Preview request JSON with pipeline config and sample logs")),
	)

	s.AddTool(previewPipelineTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_preview_logs_pipeline")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		previewObj, ok := args["preview"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("preview parameter must be a JSON object"), nil
		}
		previewJSON, err := json.Marshal(previewObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal preview: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.PreviewLogsPipeline(ctx, previewJSON)
		if err != nil {
			h.logger.Error("Failed to preview logs pipeline", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterIntegrationsHandlers(s *server.MCPServer) {
	listIntegrationsTool := mcp.NewTool("signoz_list_integrations",
		mcp.WithDescription("List all available integrations in SigNoz. Returns integration metadata including name, description, and installation status."),
	)

	s.AddTool(listIntegrationsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_integrations")
		client := h.GetClient(ctx)
		result, err := client.ListIntegrations(ctx)
		if err != nil {
			h.logger.Error("Failed to list integrations", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getIntegrationTool := mcp.NewTool("signoz_get_integration",
		mcp.WithDescription("Get details of a specific integration by ID, including configuration options and current status."),
		mcp.WithString("integrationId", mcp.Required(), mcp.Description("Integration ID")),
	)

	s.AddTool(getIntegrationTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_integration")
		integrationID, ok := req.Params.Arguments.(map[string]any)["integrationId"].(string)
		if !ok || integrationID == "" {
			return mcp.NewToolResultError("integrationId is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetIntegration(ctx, integrationID)
		if err != nil {
			h.logger.Error("Failed to get integration", zap.String("integrationId", integrationID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	installIntegrationTool := mcp.NewTool("signoz_install_integration",
		mcp.WithDescription("Install an integration. Some integrations may require configuration parameters."),
		mcp.WithString("integrationId", mcp.Required(), mcp.Description("Integration ID to install")),
		mcp.WithObject("config", mcp.Required(), mcp.Description("Installation configuration JSON (may be empty object {} if no config needed)")),
	)

	s.AddTool(installIntegrationTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_install_integration")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		integrationID, ok := args["integrationId"].(string)
		if !ok || integrationID == "" {
			return mcp.NewToolResultError("integrationId is required"), nil
		}
		configObj, ok := args["config"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("config parameter must be a JSON object"), nil
		}
		configJSON, err := json.Marshal(configObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal config: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.InstallIntegration(ctx, integrationID, configJSON)
		if err != nil {
			h.logger.Error("Failed to install integration", zap.String("integrationId", integrationID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	uninstallIntegrationTool := mcp.NewTool("signoz_uninstall_integration",
		mcp.WithDescription("Uninstall an integration by ID. This action is irreversible."),
		mcp.WithString("integrationId", mcp.Required(), mcp.Description("Integration ID to uninstall")),
	)

	s.AddTool(uninstallIntegrationTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_uninstall_integration")
		integrationID, ok := req.Params.Arguments.(map[string]any)["integrationId"].(string)
		if !ok || integrationID == "" {
			return mcp.NewToolResultError("integrationId is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.UninstallIntegration(ctx, integrationID)
		if err != nil {
			h.logger.Error("Failed to uninstall integration", zap.String("integrationId", integrationID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	connectionStatusTool := mcp.NewTool("signoz_get_integration_connection_status",
		mcp.WithDescription("Check the connection status of an installed integration. Use this to verify if an integration is properly connected and sending data."),
		mcp.WithString("integrationId", mcp.Required(), mcp.Description("Integration ID to check connection status")),
	)

	s.AddTool(connectionStatusTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_integration_connection_status")
		integrationID, ok := req.Params.Arguments.(map[string]any)["integrationId"].(string)
		if !ok || integrationID == "" {
			return mcp.NewToolResultError("integrationId is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetIntegrationConnectionStatus(ctx, integrationID)
		if err != nil {
			h.logger.Error("Failed to get integration connection status", zap.String("integrationId", integrationID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterApdexSettingsHandlers(s *server.MCPServer) {
	getApdexTool := mcp.NewTool("signoz_get_apdex_settings",
		mcp.WithDescription("Get Apdex (Application Performance Index) threshold settings for services. Returns per-service thresholds and excluded status codes."),
	)

	s.AddTool(getApdexTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_apdex_settings")
		client := h.GetClient(ctx)
		result, err := client.GetApdexSettings(ctx)
		if err != nil {
			h.logger.Error("Failed to get apdex settings", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	setApdexTool := mcp.NewTool("signoz_set_apdex_settings",
		mcp.WithDescription("Set Apdex threshold settings for a service. Fields: serviceName (string), threshold (float, e.g. 0.5 for 500ms), excludeStatusCodes (optional array of HTTP status codes to exclude)."),
		mcp.WithObject("settings", mcp.Required(), mcp.Description("Apdex settings JSON with serviceName, threshold, and optional excludeStatusCodes")),
	)

	s.AddTool(setApdexTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_set_apdex_settings")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		settingsObj, ok := args["settings"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("settings parameter must be a JSON object"), nil
		}
		settingsJSON, err := json.Marshal(settingsObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal settings: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.SetApdexSettings(ctx, settingsJSON)
		if err != nil {
			h.logger.Error("Failed to set apdex settings", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterUserManagementHandlers(s *server.MCPServer) {
	listUsersTool := mcp.NewTool("signoz_list_users",
		mcp.WithDescription("List all users in the SigNoz organization."),
	)
	s.AddTool(listUsersTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_users")
		client := h.GetClient(ctx)
		result, err := client.ListUsers(ctx)
		if err != nil {
			h.logger.Error("Failed to list users", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getUserTool := mcp.NewTool("signoz_get_user",
		mcp.WithDescription("Get details of a specific user by ID."),
		mcp.WithString("userId", mcp.Required(), mcp.Description("User ID")),
	)
	s.AddTool(getUserTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_user")
		userID, ok := req.Params.Arguments.(map[string]any)["userId"].(string)
		if !ok || userID == "" {
			return mcp.NewToolResultError("userId is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetUser(ctx, userID)
		if err != nil {
			h.logger.Error("Failed to get user", zap.String("userId", userID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	updateUserTool := mcp.NewTool("signoz_update_user",
		mcp.WithDescription("Update a user's profile. Fields: name (string), role (string), organizationId (string)."),
		mcp.WithString("userId", mcp.Required(), mcp.Description("User ID to update")),
		mcp.WithObject("user", mcp.Required(), mcp.Description("User update JSON with fields to modify")),
	)
	s.AddTool(updateUserTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_user")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		userID, ok := args["userId"].(string)
		if !ok || userID == "" {
			return mcp.NewToolResultError("userId is required"), nil
		}
		userObj, ok := args["user"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("user parameter must be a JSON object"), nil
		}
		userJSON, err := json.Marshal(userObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal user: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.UpdateUser(ctx, userID, userJSON)
		if err != nil {
			h.logger.Error("Failed to update user", zap.String("userId", userID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	deleteUserTool := mcp.NewTool("signoz_delete_user",
		mcp.WithDescription("Delete a user by ID. This action is irreversible."),
		mcp.WithString("userId", mcp.Required(), mcp.Description("User ID to delete")),
	)
	s.AddTool(deleteUserTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		userID, ok := req.Params.Arguments.(map[string]any)["userId"].(string)
		if !ok || userID == "" {
			return mcp.NewToolResultError("userId is required"), nil
		}
		h.logger.Debug("Tool called: signoz_delete_user", zap.String("userId", userID))
		client := h.GetClient(ctx)
		err := client.DeleteUser(ctx, userID)
		if err != nil {
			h.logger.Error("Failed to delete user", zap.String("userId", userID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("user deleted"), nil
	})

	listInvitesTool := mcp.NewTool("signoz_list_invites",
		mcp.WithDescription("List all pending user invitations."),
	)
	s.AddTool(listInvitesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_invites")
		client := h.GetClient(ctx)
		result, err := client.ListInvites(ctx)
		if err != nil {
			h.logger.Error("Failed to list invites", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	createInviteTool := mcp.NewTool("signoz_create_invite",
		mcp.WithDescription("Invite a new user to the SigNoz organization. Fields: email (string, required), name (string), role (string, e.g. 'ADMIN', 'EDITOR', 'VIEWER')."),
		mcp.WithObject("invite", mcp.Required(), mcp.Description("Invite JSON with email, name, and role")),
	)
	s.AddTool(createInviteTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_invite")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		inviteObj, ok := args["invite"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invite parameter must be a JSON object"), nil
		}
		inviteJSON, err := json.Marshal(inviteObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal invite: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.CreateInvite(ctx, inviteJSON)
		if err != nil {
			h.logger.Error("Failed to create invite", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	revokeInviteTool := mcp.NewTool("signoz_revoke_invite",
		mcp.WithDescription("Revoke a pending user invitation by ID."),
		mcp.WithString("inviteId", mcp.Required(), mcp.Description("Invite ID to revoke")),
	)
	s.AddTool(revokeInviteTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		inviteID, ok := req.Params.Arguments.(map[string]any)["inviteId"].(string)
		if !ok || inviteID == "" {
			return mcp.NewToolResultError("inviteId is required"), nil
		}
		h.logger.Debug("Tool called: signoz_revoke_invite", zap.String("inviteId", inviteID))
		client := h.GetClient(ctx)
		err := client.RevokeInvite(ctx, inviteID)
		if err != nil {
			h.logger.Error("Failed to revoke invite", zap.String("inviteId", inviteID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("invite revoked"), nil
	})

	listPATsTool := mcp.NewTool("signoz_list_pats",
		mcp.WithDescription("List all Personal Access Tokens (PATs)."),
	)
	s.AddTool(listPATsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_pats")
		client := h.GetClient(ctx)
		result, err := client.ListPATs(ctx)
		if err != nil {
			h.logger.Error("Failed to list PATs", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	createPATTool := mcp.NewTool("signoz_create_pat",
		mcp.WithDescription("Create a new Personal Access Token. Fields: name (string), role (string), expiresAt (optional, Unix timestamp)."),
		mcp.WithObject("pat", mcp.Required(), mcp.Description("PAT creation JSON with name, role, and optional expiresAt")),
	)
	s.AddTool(createPATTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_pat")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		patObj, ok := args["pat"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("pat parameter must be a JSON object"), nil
		}
		patJSON, err := json.Marshal(patObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal PAT: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.CreatePAT(ctx, patJSON)
		if err != nil {
			h.logger.Error("Failed to create PAT", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	updatePATTool := mcp.NewTool("signoz_update_pat",
		mcp.WithDescription("Update an existing Personal Access Token."),
		mcp.WithString("patId", mcp.Required(), mcp.Description("PAT ID to update")),
		mcp.WithObject("pat", mcp.Required(), mcp.Description("PAT update JSON with fields to modify")),
	)
	s.AddTool(updatePATTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_pat")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		patID, ok := args["patId"].(string)
		if !ok || patID == "" {
			return mcp.NewToolResultError("patId is required"), nil
		}
		patObj, ok := args["pat"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("pat parameter must be a JSON object"), nil
		}
		patJSON, err := json.Marshal(patObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal PAT: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.UpdatePAT(ctx, patID, patJSON)
		if err != nil {
			h.logger.Error("Failed to update PAT", zap.String("patId", patID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	revokePATTool := mcp.NewTool("signoz_revoke_pat",
		mcp.WithDescription("Revoke (delete) a Personal Access Token by ID. This action is irreversible."),
		mcp.WithString("patId", mcp.Required(), mcp.Description("PAT ID to revoke")),
	)
	s.AddTool(revokePATTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		patID, ok := req.Params.Arguments.(map[string]any)["patId"].(string)
		if !ok || patID == "" {
			return mcp.NewToolResultError("patId is required"), nil
		}
		h.logger.Debug("Tool called: signoz_revoke_pat", zap.String("patId", patID))
		client := h.GetClient(ctx)
		err := client.RevokePAT(ctx, patID)
		if err != nil {
			h.logger.Error("Failed to revoke PAT", zap.String("patId", patID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("PAT revoked"), nil
	})
}

func (h *Handler) RegisterRoleManagementHandlers(s *server.MCPServer) {
	listRolesTool := mcp.NewTool("signoz_list_roles",
		mcp.WithDescription("List all roles in the SigNoz organization."),
	)
	s.AddTool(listRolesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_roles")
		client := h.GetClient(ctx)
		result, err := client.ListRoles(ctx)
		if err != nil {
			h.logger.Error("Failed to list roles", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getRoleTool := mcp.NewTool("signoz_get_role",
		mcp.WithDescription("Get details of a specific role by ID."),
		mcp.WithString("roleId", mcp.Required(), mcp.Description("Role ID")),
	)
	s.AddTool(getRoleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_role")
		roleID, ok := req.Params.Arguments.(map[string]any)["roleId"].(string)
		if !ok || roleID == "" {
			return mcp.NewToolResultError("roleId is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetRole(ctx, roleID)
		if err != nil {
			h.logger.Error("Failed to get role", zap.String("roleId", roleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	createRoleTool := mcp.NewTool("signoz_create_role",
		mcp.WithDescription("Create a new role with specified permissions."),
		mcp.WithObject("role", mcp.Required(), mcp.Description("Role JSON with name and permissions configuration")),
	)
	s.AddTool(createRoleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_role")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		roleObj, ok := args["role"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("role parameter must be a JSON object"), nil
		}
		roleJSON, err := json.Marshal(roleObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal role: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.CreateRole(ctx, roleJSON)
		if err != nil {
			h.logger.Error("Failed to create role", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	updateRoleTool := mcp.NewTool("signoz_update_role",
		mcp.WithDescription("Update an existing role. Uses PATCH method — only provided fields are modified."),
		mcp.WithString("roleId", mcp.Required(), mcp.Description("Role ID to update")),
		mcp.WithObject("role", mcp.Required(), mcp.Description("Partial role JSON with fields to modify")),
	)
	s.AddTool(updateRoleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_role")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		roleID, ok := args["roleId"].(string)
		if !ok || roleID == "" {
			return mcp.NewToolResultError("roleId is required"), nil
		}
		roleObj, ok := args["role"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("role parameter must be a JSON object"), nil
		}
		roleJSON, err := json.Marshal(roleObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal role: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.UpdateRole(ctx, roleID, roleJSON)
		if err != nil {
			h.logger.Error("Failed to update role", zap.String("roleId", roleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	deleteRoleTool := mcp.NewTool("signoz_delete_role",
		mcp.WithDescription("Delete a role by ID. This action is irreversible. Ensure no users are assigned this role before deleting."),
		mcp.WithString("roleId", mcp.Required(), mcp.Description("Role ID to delete")),
	)
	s.AddTool(deleteRoleTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		roleID, ok := req.Params.Arguments.(map[string]any)["roleId"].(string)
		if !ok || roleID == "" {
			return mcp.NewToolResultError("roleId is required"), nil
		}
		h.logger.Debug("Tool called: signoz_delete_role", zap.String("roleId", roleID))
		client := h.GetClient(ctx)
		err := client.DeleteRole(ctx, roleID)
		if err != nil {
			h.logger.Error("Failed to delete role", zap.String("roleId", roleID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("role deleted"), nil
	})
}

func (h *Handler) RegisterCloudIntegrationsHandlers(s *server.MCPServer) {
	listAccountsTool := mcp.NewTool("signoz_list_cloud_accounts",
		mcp.WithDescription("List all connected cloud provider accounts. Currently supports AWS."),
		mcp.WithString("cloudProvider", mcp.Required(), mcp.Description("Cloud provider: 'aws'")),
	)
	s.AddTool(listAccountsTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_list_cloud_accounts")
		provider, ok := req.Params.Arguments.(map[string]any)["cloudProvider"].(string)
		if !ok || provider == "" {
			return mcp.NewToolResultError("cloudProvider is required (e.g. 'aws')"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.ListCloudAccounts(ctx, provider)
		if err != nil {
			h.logger.Error("Failed to list cloud accounts", zap.String("provider", provider), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	getAccountTool := mcp.NewTool("signoz_get_cloud_account",
		mcp.WithDescription("Get details of a specific cloud provider account."),
		mcp.WithString("cloudProvider", mcp.Required(), mcp.Description("Cloud provider: 'aws'")),
		mcp.WithString("accountId", mcp.Required(), mcp.Description("Cloud account ID")),
	)
	s.AddTool(getAccountTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_cloud_account")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		provider, ok := args["cloudProvider"].(string)
		if !ok || provider == "" {
			return mcp.NewToolResultError("cloudProvider is required"), nil
		}
		accountID, ok := args["accountId"].(string)
		if !ok || accountID == "" {
			return mcp.NewToolResultError("accountId is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetCloudAccount(ctx, provider, accountID)
		if err != nil {
			h.logger.Error("Failed to get cloud account", zap.String("provider", provider), zap.String("accountId", accountID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	createAccountTool := mcp.NewTool("signoz_create_cloud_account",
		mcp.WithDescription("Connect a new cloud provider account for monitoring. For AWS: provide roleArn and externalId."),
		mcp.WithString("cloudProvider", mcp.Required(), mcp.Description("Cloud provider: 'aws'")),
		mcp.WithObject("account", mcp.Required(), mcp.Description("Account config JSON (e.g. for AWS: {roleArn, externalId})")),
	)
	s.AddTool(createAccountTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_create_cloud_account")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		provider, ok := args["cloudProvider"].(string)
		if !ok || provider == "" {
			return mcp.NewToolResultError("cloudProvider is required"), nil
		}
		accountObj, ok := args["account"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("account parameter must be a JSON object"), nil
		}
		accountJSON, err := json.Marshal(accountObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal account: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.CreateCloudAccount(ctx, provider, accountJSON)
		if err != nil {
			h.logger.Error("Failed to create cloud account", zap.String("provider", provider), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	updateAccountTool := mcp.NewTool("signoz_update_cloud_account",
		mcp.WithDescription("Update a cloud provider account configuration."),
		mcp.WithString("cloudProvider", mcp.Required(), mcp.Description("Cloud provider: 'aws'")),
		mcp.WithString("accountId", mcp.Required(), mcp.Description("Cloud account ID to update")),
		mcp.WithObject("account", mcp.Required(), mcp.Description("Updated account config JSON")),
	)
	s.AddTool(updateAccountTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_update_cloud_account")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		provider, ok := args["cloudProvider"].(string)
		if !ok || provider == "" {
			return mcp.NewToolResultError("cloudProvider is required"), nil
		}
		accountID, ok := args["accountId"].(string)
		if !ok || accountID == "" {
			return mcp.NewToolResultError("accountId is required"), nil
		}
		accountObj, ok := args["account"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("account parameter must be a JSON object"), nil
		}
		accountJSON, err := json.Marshal(accountObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal account: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.UpdateCloudAccount(ctx, provider, accountID, accountJSON)
		if err != nil {
			h.logger.Error("Failed to update cloud account", zap.String("provider", provider), zap.String("accountId", accountID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	deleteAccountTool := mcp.NewTool("signoz_delete_cloud_account",
		mcp.WithDescription("Delete a cloud provider account connection. This action is irreversible."),
		mcp.WithString("cloudProvider", mcp.Required(), mcp.Description("Cloud provider: 'aws'")),
		mcp.WithString("accountId", mcp.Required(), mcp.Description("Cloud account ID to delete")),
	)
	s.AddTool(deleteAccountTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		provider, ok := args["cloudProvider"].(string)
		if !ok || provider == "" {
			return mcp.NewToolResultError("cloudProvider is required"), nil
		}
		accountID, ok := args["accountId"].(string)
		if !ok || accountID == "" {
			return mcp.NewToolResultError("accountId is required"), nil
		}
		h.logger.Debug("Tool called: signoz_delete_cloud_account", zap.String("provider", provider), zap.String("accountId", accountID))
		client := h.GetClient(ctx)
		err := client.DeleteCloudAccount(ctx, provider, accountID)
		if err != nil {
			h.logger.Error("Failed to delete cloud account", zap.String("provider", provider), zap.String("accountId", accountID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("cloud account deleted"), nil
	})

	accountServicesTool := mcp.NewTool("signoz_get_cloud_account_services",
		mcp.WithDescription("Get connected services for a cloud provider account. Shows which AWS services are sending data."),
		mcp.WithString("cloudProvider", mcp.Required(), mcp.Description("Cloud provider: 'aws'")),
		mcp.WithString("accountId", mcp.Required(), mcp.Description("Cloud account ID")),
	)
	s.AddTool(accountServicesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_cloud_account_services")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		provider, ok := args["cloudProvider"].(string)
		if !ok || provider == "" {
			return mcp.NewToolResultError("cloudProvider is required"), nil
		}
		accountID, ok := args["accountId"].(string)
		if !ok || accountID == "" {
			return mcp.NewToolResultError("accountId is required"), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetCloudAccountServices(ctx, provider, accountID)
		if err != nil {
			h.logger.Error("Failed to get cloud account services", zap.String("provider", provider), zap.String("accountId", accountID), zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}

func (h *Handler) RegisterMessagingQueuesHandlers(s *server.MCPServer) {
	consumerLagTool := mcp.NewTool("signoz_get_kafka_consumer_lag",
		mcp.WithDescription("Get Kafka consumer lag details for a given consumer group and topic. Returns consumer lag data including partition assignments and lag metrics. Request body should include start/end timestamps (as string nanoseconds) and variables with consumer_group and topic."),
		mcp.WithObject("query", mcp.Required(), mcp.Description("Query JSON with start, end (Unix ms timestamps), and variables object")),
	)
	s.AddTool(consumerLagTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_kafka_consumer_lag")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		queryObj, ok := args["query"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("query parameter must be a JSON object"), nil
		}
		queryJSON, err := json.Marshal(queryObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal query: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetKafkaConsumerLagOverview(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to get Kafka consumer lag", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	partitionLatencyTool := mcp.NewTool("signoz_get_kafka_partition_latency",
		mcp.WithDescription("Get Kafka partition latency overview. Shows per-partition latency metrics. Request body requires start, end, and variables."),
		mcp.WithObject("query", mcp.Required(), mcp.Description("Query JSON with start, end (Unix ms timestamps), and variables object")),
	)
	s.AddTool(partitionLatencyTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_kafka_partition_latency")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		queryObj, ok := args["query"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("query parameter must be a JSON object"), nil
		}
		queryJSON, err := json.Marshal(queryObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal query: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetKafkaPartitionLatency(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to get Kafka partition latency", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})

	producerOverviewTool := mcp.NewTool("signoz_get_kafka_producer_overview",
		mcp.WithDescription("Get Kafka topic throughput producer overview. Returns producer throughput data for specified topics. Request body should include start/end timestamps (as string nanoseconds) and variables with topic."),
		mcp.WithObject("query", mcp.Required(), mcp.Description("Query JSON with start, end (Unix ms timestamps), and variables object")),
	)
	s.AddTool(producerOverviewTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		h.logger.Debug("Tool called: signoz_get_kafka_producer_overview")
		args, ok := req.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("invalid arguments payload"), nil
		}
		queryObj, ok := args["query"].(map[string]any)
		if !ok {
			return mcp.NewToolResultError("query parameter must be a JSON object"), nil
		}
		queryJSON, err := json.Marshal(queryObj)
		if err != nil {
			return mcp.NewToolResultError("failed to marshal query: " + err.Error()), nil
		}
		client := h.GetClient(ctx)
		result, err := client.GetKafkaProducerOverview(ctx, queryJSON)
		if err != nil {
			h.logger.Error("Failed to get Kafka producer overview", zap.Error(err))
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(result)), nil
	})
}
