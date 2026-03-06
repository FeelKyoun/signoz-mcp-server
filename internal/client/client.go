package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/SigNoz/signoz-mcp-server/pkg/types"
)

// isHTMLResponse detects when SigNoz returns its SPA HTML instead of a JSON API response.
// This happens when the requested API route doesn't exist and SigNoz falls back to serving the frontend.
func isHTMLResponse(body []byte) bool {
	// Avoid allocating a full string copy — check bytes directly after trimming whitespace.
	b := bytes.TrimSpace(body)
	return bytes.HasPrefix(b, []byte("<!doctype html>")) ||
		bytes.HasPrefix(b, []byte("<!DOCTYPE html>")) ||
		bytes.HasPrefix(b, []byte("<html"))
}

const (
	SignozApiKey    = "SIGNOZ-API-KEY"
	ContentType    = "Content-Type"
	defaultTimeout = 30 * time.Second
)

// sharedTransport is reused across all SigNoz clients to share connection pools.
var sharedTransport = &http.Transport{
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 20,
	IdleConnTimeout:     90 * time.Second,
}

type SigNoz struct {
	baseURL    string
	apiKey     string
	logger     *zap.Logger
	httpClient *http.Client
}

func NewClient(log *zap.Logger, url, apiKey string) *SigNoz {
	return &SigNoz{
		logger:  log,
		baseURL: url,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Transport: sharedTransport,
		},
	}
}

// doJSON performs an HTTP request and returns the response body as json.RawMessage.
// It handles header setting, timeout, status checking, HTML detection, and body reading.
func (s *SigNoz) doJSON(ctx context.Context, method, path string, body io.Reader) (json.RawMessage, error) {
	reqURL := s.baseURL + path

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	s.logger.Debug("Making request to SigNoz API", zap.String("method", method), zap.String("path", path))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", reqURL), zap.Error(err))
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", reqURL), zap.Error(err))
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := string(respBody)
		s.logger.Error("API request failed", zap.String("url", reqURL), zap.Int("status", resp.StatusCode), zap.String("response", msg))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, msg)
	}

	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}

	return respBody, nil
}

// doAction performs an HTTP request and discards the response body. Used for DELETE/PUT that return no content.
func (s *SigNoz) doAction(ctx context.Context, method, path string, body io.Reader) error {
	reqURL := s.baseURL + path

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	s.logger.Debug("Making request to SigNoz API", zap.String("method", method), zap.String("path", path))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", reqURL), zap.Error(err))
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		msg := string(respBody)
		s.logger.Error("API request failed", zap.String("url", reqURL), zap.Int("status", resp.StatusCode), zap.String("response", msg))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, msg)
	}

	return nil
}

// jsonBody marshals v to JSON and returns a reader. Panics on marshal failure
// since callers pass known-marshalable types (maps, structs).
func jsonBody(v any) io.Reader {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("jsonBody: failed to marshal %T: %v", v, err))
	}
	return bytes.NewReader(data)
}

// === Metrics ===

func (s *SigNoz) ListMetricKeys(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/metrics/filters/keys", nil)
}

func (s *SigNoz) SearchMetricByText(ctx context.Context, searchText string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v3/autocomplete/aggregate_attributes?dataSource=metrics&searchText="+url.QueryEscape(searchText), nil)
}

func (s *SigNoz) GetMetricsAvailableFields(ctx context.Context, searchText string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v3/autocomplete/aggregate_attributes?aggregateOperator=avg&searchText="+url.QueryEscape(searchText)+"&dataSource=metrics", nil)
}

func (s *SigNoz) GetMetricsFieldValues(ctx context.Context, fieldName string, searchText string) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/v1/fields/keys?signal=metrics&metricName=%s&searchText=%s&fieldContext=&fieldDataType=&source=",
		url.QueryEscape(fieldName), url.QueryEscape(searchText))
	return s.doJSON(ctx, http.MethodGet, path, nil)
}

// === Alerts ===

func (s *SigNoz) ListAlerts(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/alerts", nil)
}

func (s *SigNoz) GetAlertByRuleID(ctx context.Context, ruleID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/rules/"+ruleID, nil)
}

func (s *SigNoz) CreateAlertRule(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
}

func (s *SigNoz) UpdateAlertRule(ctx context.Context, ruleID string, body json.RawMessage) error {
	return s.doAction(ctx, http.MethodPut, "/api/v1/rules/"+ruleID, bytes.NewReader(body))
}

func (s *SigNoz) DeleteAlertRule(ctx context.Context, ruleID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/rules/"+ruleID, nil)
}

func (s *SigNoz) GetAlertHistory(ctx context.Context, ruleID string, req types.AlertHistoryRequest) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/v1/rules/%s/history/timeline", ruleID)
	return s.doJSON(ctx, http.MethodPost, path, jsonBody(req))
}

// === Dashboards ===

// ListDashboards returns a simplified list of dashboards (uuid, name, description, tags, metadata).
func (s *SigNoz) ListDashboards(ctx context.Context) (json.RawMessage, error) {
	body, err := s.doJSON(ctx, http.MethodGet, "/api/v1/dashboards", nil)
	if err != nil {
		return nil, err
	}

	var rawResponse map[string]interface{}
	if err := json.Unmarshal(body, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	data, ok := rawResponse["data"].([]interface{})
	if !ok {
		return body, nil
	}

	simplifiedDashboards := make([]map[string]interface{}, 0, len(data))
	for _, dashboard := range data {
		dash, ok := dashboard.(map[string]interface{})
		if !ok {
			continue
		}
		var name, desc, tags any
		if dashData, ok := dash["data"].(map[string]interface{}); ok {
			name = dashData["title"]
			desc = dashData["description"]
			tags = dashData["tags"]
		}
		simplifiedDashboards = append(simplifiedDashboards, map[string]interface{}{
			"uuid":        dash["id"],
			"name":        name,
			"description": desc,
			"tags":        tags,
			"createdAt":   dash["createdAt"],
			"updatedAt":   dash["updatedAt"],
			"createdBy":   dash["createdBy"],
			"updatedBy":   dash["updatedBy"],
		})
	}

	return json.Marshal(map[string]interface{}{
		"status": rawResponse["status"],
		"data":   simplifiedDashboards,
	})
}

func (s *SigNoz) GetDashboard(ctx context.Context, uuid string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/dashboards/"+uuid, nil)
}

func (s *SigNoz) CreateDashboard(ctx context.Context, dashboard types.Dashboard) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/dashboards", jsonBody(dashboard))
}

func (s *SigNoz) UpdateDashboard(ctx context.Context, id string, dashboard types.Dashboard) error {
	return s.doAction(ctx, http.MethodPut, "/api/v1/dashboards/"+id, jsonBody(dashboard))
}

func (s *SigNoz) DeleteDashboard(ctx context.Context, uuid string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/dashboards/"+uuid, nil)
}

// === Services ===

func (s *SigNoz) ListServices(ctx context.Context, start, end string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/services", jsonBody(map[string]string{
		"start": start,
		"end":   end,
	}))
}

func (s *SigNoz) GetServiceTopOperations(ctx context.Context, start, end, service string, tags json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/service/top_operations", jsonBody(map[string]any{
		"start":   start,
		"end":     end,
		"service": service,
		"tags":    tags,
	}))
}

// === Query Builder ===

func (s *SigNoz) QueryBuilderV5(ctx context.Context, body []byte) (json.RawMessage, error) {
	s.logger.Debug("sending query builder v5 request", zap.ByteString("body", body))
	return s.doJSON(ctx, http.MethodPost, "/api/v5/query_range", bytes.NewReader(body))
}

// === Traces ===

func (s *SigNoz) GetTraceDetails(ctx context.Context, traceID string, includeSpans bool, startTime, endTime int64) (json.RawMessage, error) {
	if startTime == 0 || endTime == 0 {
		return nil, fmt.Errorf("start and end time parameters are required")
	}
	filterExpression := fmt.Sprintf("traceID = '%s'", traceID)
	queryPayload := types.BuildTracesQueryPayload(startTime, endTime, filterExpression, 1000)
	queryJSON, err := json.Marshal(queryPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query payload: %w", err)
	}
	return s.QueryBuilderV5(ctx, queryJSON)
}

func (s *SigNoz) GetTraceErrorAnalysis(ctx context.Context, startTime, endTime int64, serviceName string) (json.RawMessage, error) {
	filterExpression := "hasError = true"
	if serviceName != "" {
		filterExpression += fmt.Sprintf(" AND service.name in ['%s']", serviceName)
	}
	queryPayload := types.BuildTracesQueryPayload(startTime, endTime, filterExpression, 1000)
	queryJSON, err := json.Marshal(queryPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query payload: %w", err)
	}
	return s.QueryBuilderV5(ctx, queryJSON)
}

func (s *SigNoz) GetTraceSpanHierarchy(ctx context.Context, traceID string, startTime, endTime int64) (json.RawMessage, error) {
	if startTime == 0 || endTime == 0 {
		return nil, fmt.Errorf("start and end time parameters are required")
	}
	filterExpression := fmt.Sprintf("traceID = '%s'", traceID)
	queryPayload := types.BuildTracesQueryPayload(startTime, endTime, filterExpression, 1000)
	queryJSON, err := json.Marshal(queryPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query payload: %w", err)
	}
	return s.QueryBuilderV5(ctx, queryJSON)
}

func (s *SigNoz) GetTraceFieldValues(ctx context.Context, fieldName string, searchText string) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/v1/fields/values?signal=traces&name=%s&searchText=%s&metricName=&source=meter",
		url.QueryEscape(fieldName), url.QueryEscape(searchText))
	return s.doJSON(ctx, http.MethodGet, path, nil)
}

func (s *SigNoz) GetTraceAvailableFields(ctx context.Context, searchText string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v3/autocomplete/attribute_keys?aggregateOperator=noop&searchText="+url.QueryEscape(searchText)+"&dataSource=traces&aggregateAttribute=&tagType=", nil)
}

// === Logs ===

func (s *SigNoz) ListLogViews(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/explorer/views?sourcePage=logs", nil)
}

func (s *SigNoz) GetLogView(ctx context.Context, viewID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/explorer/views/"+viewID, nil)
}

func (s *SigNoz) GetLogsAvailableFields(ctx context.Context, searchText string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v3/filter_suggestions?searchText="+url.QueryEscape(searchText)+"&dataSource=logs&existingFilter=e30", nil)
}

func (s *SigNoz) GetLogsFieldValues(ctx context.Context, fieldName string, searchText string) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/v3/autocomplete/attribute_values?aggregateOperator=noop&dataSource=logs&aggregateAttribute=&attributeKey=%s&searchText=%s&filterAttributeKeyDataType=string&tagType=resource",
		url.QueryEscape(fieldName), url.QueryEscape(searchText))
	return s.doJSON(ctx, http.MethodGet, path, nil)
}

// === Saved Views ===

func (s *SigNoz) CreateSavedView(ctx context.Context, savedView types.SavedView) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/explorer/views", jsonBody(savedView))
}

func (s *SigNoz) UpdateSavedView(ctx context.Context, viewID string, savedView types.SavedView) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPut, "/api/v1/explorer/views/"+viewID, jsonBody(savedView))
}

func (s *SigNoz) DeleteSavedView(ctx context.Context, viewID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/explorer/views/"+viewID, nil)
}

// === Notification Channels ===

func (s *SigNoz) ListNotificationChannels(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/channels", nil)
}

func (s *SigNoz) GetNotificationChannel(ctx context.Context, channelID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/channels/"+channelID, nil)
}

func (s *SigNoz) CreateNotificationChannel(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/channels", bytes.NewReader(body))
}

func (s *SigNoz) UpdateNotificationChannel(ctx context.Context, channelID string, body json.RawMessage) error {
	return s.doAction(ctx, http.MethodPut, "/api/v1/channels/"+channelID, bytes.NewReader(body))
}

func (s *SigNoz) DeleteNotificationChannel(ctx context.Context, channelID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/channels/"+channelID, nil)
}

// === Downtime Schedules ===

func (s *SigNoz) ListDowntimeSchedules(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/downtime_schedules", nil)
}

func (s *SigNoz) GetDowntimeSchedule(ctx context.Context, scheduleID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/downtime_schedules/"+scheduleID, nil)
}

func (s *SigNoz) CreateDowntimeSchedule(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/downtime_schedules", bytes.NewReader(body))
}

func (s *SigNoz) UpdateDowntimeSchedule(ctx context.Context, scheduleID string, body json.RawMessage) error {
	return s.doAction(ctx, http.MethodPut, "/api/v1/downtime_schedules/"+scheduleID, bytes.NewReader(body))
}

func (s *SigNoz) DeleteDowntimeSchedule(ctx context.Context, scheduleID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/downtime_schedules/"+scheduleID, nil)
}

// === Alert Route Policies ===

func (s *SigNoz) ListRoutePolicies(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/route_policies", nil)
}

func (s *SigNoz) GetRoutePolicy(ctx context.Context, policyID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/route_policies/"+policyID, nil)
}

func (s *SigNoz) CreateRoutePolicy(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/route_policies", bytes.NewReader(body))
}

func (s *SigNoz) UpdateRoutePolicy(ctx context.Context, policyID string, body json.RawMessage) error {
	return s.doAction(ctx, http.MethodPut, "/api/v1/route_policies/"+policyID, bytes.NewReader(body))
}

func (s *SigNoz) DeleteRoutePolicy(ctx context.Context, policyID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/route_policies/"+policyID, nil)
}

// === Dependency Graph ===

func (s *SigNoz) GetDependencyGraph(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/dependency_graph", bytes.NewReader(body))
}

// === TTL / Retention Settings ===

func (s *SigNoz) GetTTLSettings(ctx context.Context, signalType string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/settings/ttl?type="+url.QueryEscape(signalType), nil)
}

func (s *SigNoz) SetTTLSettings(ctx context.Context, signalType string, duration string) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/v1/settings/ttl?type=%s&duration=%s", url.QueryEscape(signalType), url.QueryEscape(duration))
	return s.doJSON(ctx, http.MethodPost, path, nil)
}

func (s *SigNoz) GetTTLSettingsV2(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v2/settings/ttl", nil)
}

func (s *SigNoz) SetTTLSettingsV2(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v2/settings/ttl", bytes.NewReader(body))
}

// === Infra Metrics K8s ===

func (s *SigNoz) ListInfraResources(ctx context.Context, resourceType string, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/"+resourceType+"/list", bytes.NewReader(body))
}

func (s *SigNoz) GetInfraAttributeKeys(ctx context.Context, resourceType string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/"+resourceType+"/attribute_keys?dataSource=metrics", nil)
}

func (s *SigNoz) GetInfraAttributeValues(ctx context.Context, resourceType string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/"+resourceType+"/attribute_values?dataSource=metrics", nil)
}

// === Logs Pipelines ===

func (s *SigNoz) GetLogsPipelines(ctx context.Context, version string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/logs/pipelines/"+version, nil)
}

func (s *SigNoz) SaveLogsPipelines(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/logs/pipelines", bytes.NewReader(body))
}

func (s *SigNoz) PreviewLogsPipeline(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/logs/pipelines/preview", bytes.NewReader(body))
}

// === Integrations ===

func (s *SigNoz) ListIntegrations(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/integrations", nil)
}

func (s *SigNoz) GetIntegration(ctx context.Context, integrationID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/integrations/"+integrationID, nil)
}

func (s *SigNoz) InstallIntegration(ctx context.Context, integrationID string, body json.RawMessage) (json.RawMessage, error) {
	reqBody := map[string]interface{}{"integration_id": integrationID}
	if len(body) > 0 {
		var configMap map[string]interface{}
		if err := json.Unmarshal(body, &configMap); err == nil {
			for k, v := range configMap {
				reqBody[k] = v
			}
		}
	}
	return s.doJSON(ctx, http.MethodPost, "/api/v1/integrations/install", jsonBody(reqBody))
}

func (s *SigNoz) UninstallIntegration(ctx context.Context, integrationID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/integrations/uninstall", jsonBody(map[string]string{"integration_id": integrationID}))
}

func (s *SigNoz) GetIntegrationConnectionStatus(ctx context.Context, integrationID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/integrations/"+integrationID+"/connection_status", nil)
}

// === Apdex Settings ===

func (s *SigNoz) GetApdexSettings(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/settings/apdex", nil)
}

func (s *SigNoz) SetApdexSettings(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/settings/apdex", bytes.NewReader(body))
}

// === User Management ===

func (s *SigNoz) ListUsers(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/user", nil)
}

func (s *SigNoz) GetUser(ctx context.Context, userID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/user/"+userID, nil)
}

func (s *SigNoz) UpdateUser(ctx context.Context, userID string, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPut, "/api/v1/user/"+userID, bytes.NewReader(body))
}

func (s *SigNoz) DeleteUser(ctx context.Context, userID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/user/"+userID, nil)
}

func (s *SigNoz) ListInvites(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/invite", nil)
}

func (s *SigNoz) CreateInvite(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/invite", bytes.NewReader(body))
}

func (s *SigNoz) RevokeInvite(ctx context.Context, inviteID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/invite/"+inviteID, nil)
}

func (s *SigNoz) ListPATs(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/pats", nil)
}

func (s *SigNoz) CreatePAT(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/pats", bytes.NewReader(body))
}

func (s *SigNoz) UpdatePAT(ctx context.Context, patID string, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPut, "/api/v1/pats/"+patID, bytes.NewReader(body))
}

func (s *SigNoz) RevokePAT(ctx context.Context, patID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/pats/"+patID, nil)
}

// === Role Management ===

func (s *SigNoz) ListRoles(ctx context.Context) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/roles", nil)
}

func (s *SigNoz) GetRole(ctx context.Context, roleID string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/roles/"+roleID, nil)
}

func (s *SigNoz) CreateRole(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/roles", bytes.NewReader(body))
}

func (s *SigNoz) UpdateRole(ctx context.Context, roleID string, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPatch, "/api/v1/roles/"+roleID, bytes.NewReader(body))
}

func (s *SigNoz) DeleteRole(ctx context.Context, roleID string) error {
	return s.doAction(ctx, http.MethodDelete, "/api/v1/roles/"+roleID, nil)
}

// === Cloud Integrations ===

func (s *SigNoz) ListCloudAccounts(ctx context.Context, cloudProvider string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/cloud-integrations/"+cloudProvider+"/accounts", nil)
}

func (s *SigNoz) GetCloudAccount(ctx context.Context, cloudProvider string, accountID string) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/v1/cloud-integrations/%s/accounts/%s/status", cloudProvider, accountID)
	return s.doJSON(ctx, http.MethodGet, path, nil)
}

func (s *SigNoz) CreateCloudAccount(ctx context.Context, cloudProvider string, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/cloud-integrations/"+cloudProvider+"/accounts/generate-connection-url", bytes.NewReader(body))
}

func (s *SigNoz) UpdateCloudAccount(ctx context.Context, cloudProvider string, accountID string, body json.RawMessage) (json.RawMessage, error) {
	path := fmt.Sprintf("/api/v1/cloud-integrations/%s/accounts/%s/config", cloudProvider, accountID)
	return s.doJSON(ctx, http.MethodPost, path, bytes.NewReader(body))
}

func (s *SigNoz) DeleteCloudAccount(ctx context.Context, cloudProvider string, accountID string) error {
	path := fmt.Sprintf("/api/v1/cloud-integrations/%s/accounts/%s/disconnect", cloudProvider, accountID)
	return s.doAction(ctx, http.MethodPost, path, strings.NewReader("{}"))
}

func (s *SigNoz) GetCloudAccountServices(ctx context.Context, cloudProvider string) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodGet, "/api/v1/cloud-integrations/"+cloudProvider+"/services", nil)
}

// === Messaging Queues (Kafka) ===

func (s *SigNoz) GetKafkaConsumerLagOverview(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/messaging-queues/kafka/consumer-lag/consumer-details", bytes.NewReader(body))
}

func (s *SigNoz) GetKafkaPartitionLatency(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/messaging-queues/kafka/partition-latency/overview", bytes.NewReader(body))
}

func (s *SigNoz) GetKafkaProducerOverview(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	return s.doJSON(ctx, http.MethodPost, "/api/v1/messaging-queues/kafka/topic-throughput/producer", bytes.NewReader(body))
}
