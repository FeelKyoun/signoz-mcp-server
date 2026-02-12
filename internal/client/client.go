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
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "<!doctype html>") || strings.HasPrefix(trimmed, "<!DOCTYPE html>") || strings.HasPrefix(trimmed, "<html")
}

const (
	SignozApiKey = "SIGNOZ-API-KEY"
	ContentType  = "Content-Type"
)

type SigNoz struct {
	baseURL string
	apiKey  string
	logger  *zap.Logger
}

func NewClient(log *zap.Logger, url, apiKey string) *SigNoz {
	return &SigNoz{logger: log, baseURL: url, apiKey: apiKey}
}

func (s *SigNoz) ListMetricKeys(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/metrics/filters/keys", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Making request to SigNoz API", zap.String("method", "GET"), zap.String("endpoint", "/api/v1/metrics/filters/keys"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Successfully retrieved metric keys", zap.String("url", url), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) SearchMetricByText(ctx context.Context, searchText string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v3/autocomplete/aggregate_attributes?dataSource=metrics&searchText=%s", s.baseURL, searchText)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Searching metric names (aggregate_attributes)", zap.String("searchText", searchText))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("searchText", searchText), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Successfully searched metric names", zap.String("searchText", searchText), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) ListAlerts(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/alerts", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching alerts from SigNoz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Successfully retrieved alerts", zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetAlertByRuleID(ctx context.Context, ruleID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/rules/%s", s.baseURL, ruleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching alert rule details", zap.String("ruleID", ruleID))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("ruleID", ruleID), zap.Error(err))
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("read error: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Debug("Successfully retrieved alert rule", zap.String("ruleID", ruleID), zap.Int("status", resp.StatusCode))
	return body, nil
}

// ListDashboards filters data as it returns too much of data even the ui tags
// so we filter and only return required information which might help to get
// detailed info of a dashboard.
func (s *SigNoz) ListDashboards(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/dashboards", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching dashboards from SigNoz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rawResponse map[string]interface{}
	if err := json.Unmarshal(body, &rawResponse); err != nil {
		s.logger.Error("Failed to parse response", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if data, ok := rawResponse["data"].([]interface{}); ok {
		simplifiedDashboards := make([]map[string]interface{}, 0, len(data))

		for _, dashboard := range data {
			if dash, ok := dashboard.(map[string]interface{}); ok {
				var (
					dashData map[string]interface{}
					name     any
					desc     any
					tags     any
				)
				if v, ok := dash["data"].(map[string]interface{}); ok {
					dashData = v
					name = dashData["title"]
					desc = dashData["description"]
					tags = dashData["tags"]
				}

				simplified := map[string]interface{}{
					"uuid":        dash["id"],
					"name":        name,
					"description": desc,
					"tags":        tags,
					"createdAt":   dash["createdAt"],
					"updatedAt":   dash["updatedAt"],
					"createdBy":   dash["createdBy"],
					"updatedBy":   dash["updatedBy"],
				}
				simplifiedDashboards = append(simplifiedDashboards, simplified)
			}
		}

		simplifiedResponse := map[string]interface{}{
			"status": rawResponse["status"],
			"data":   simplifiedDashboards,
		}

		simplifiedJSON, err := json.Marshal(simplifiedResponse)
		if err != nil {
			s.logger.Error("Failed to marshal simplified response", zap.Error(err))
			return nil, fmt.Errorf("failed to marshal simplified response: %w", err)
		}

		s.logger.Debug("Successfully retrieved and simplified dashboards", zap.Int("count", len(simplifiedDashboards)), zap.Int("status", resp.StatusCode))
		return simplifiedJSON, nil
	}

	s.logger.Debug("Successfully retrieved dashboards", zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetDashboard(ctx context.Context, uuid string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/dashboards/%s", s.baseURL, uuid)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching dashboard details", zap.String("uuid", uuid))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("uuid", uuid), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved dashboard", zap.String("uuid", uuid), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) ListServices(ctx context.Context, start, end string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/services", s.baseURL)

	payload := map[string]string{
		"start": start,
		"end":   end,
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	s.logger.Debug("Fetching services from SigNoz", zap.String("start", start), zap.String("end", end))

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("start", start), zap.String("end", end), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved services", zap.String("start", start), zap.String("end", end), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetServiceTopOperations(ctx context.Context, start, end, service string, tags json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/service/top_operations", s.baseURL)

	payload := map[string]any{
		"start":   start,
		"end":     end,
		"service": service,
		"tags":    tags,
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	s.logger.Debug("Fetching service top operations", zap.String("start", start), zap.String("end", end), zap.String("service", service))

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("start", start), zap.String("end", end), zap.String("service", service), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved service top operations", zap.String("start", start), zap.String("end", end), zap.String("service", service), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) QueryBuilderV5(ctx context.Context, body []byte) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v5/query_range", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("sending request", zap.String("url", url), zap.ByteString("body", body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(b))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return b, nil
}

func (s *SigNoz) GetAlertHistory(ctx context.Context, ruleID string, req types.AlertHistoryRequest) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/rules/%s/history/timeline", s.baseURL, ruleID)
	// includes ruleid to get history
	// eg: /api/v1/rules/<ruleID>/history/timeline

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set(ContentType, "application/json")
	httpReq.Header.Set(SignozApiKey, s.apiKey)

	s.logger.Debug("sending request", zap.String("url", url), zap.ByteString("body", reqBody))

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)

	s.logger.Debug("Making request to SigNoz API",
		zap.String("method", "POST"),
		zap.String("endpoint", fmt.Sprintf("/api/v1/rules/%s/history/timeline", ruleID)))

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.Error(err))
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("API request failed",
			zap.String("url", url),
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (s *SigNoz) ListLogViews(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/explorer/views?sourcePage=logs", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching log views from SigNoz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved log views", zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetLogView(ctx context.Context, viewID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/explorer/views/%s", s.baseURL, viewID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching log view details", zap.String("viewID", viewID))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("viewID", viewID), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved log view", zap.String("viewID", viewID), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetTraceFieldValues(ctx context.Context, fieldName string, searchText string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/fields/values?signal=traces&name=%s&searchText=%s&metricName=&source=meter", s.baseURL, fieldName, searchText)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching trace field values", zap.String("fieldName", fieldName), zap.String("searchText", searchText))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("fieldName", fieldName), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved trace field values", zap.String("fieldName", fieldName), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetTraceAvailableFields(ctx context.Context, searchText string) (json.RawMessage, error) {
	encodedSearchText := url.QueryEscape(searchText)
	urlStr := fmt.Sprintf("%s/api/v3/autocomplete/attribute_keys?aggregateOperator=noop&searchText=%s&dataSource=traces&aggregateAttribute=&tagType=", s.baseURL, encodedSearchText)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching trace available fields", zap.String("searchText", searchText))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", urlStr), zap.String("searchText", searchText), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", urlStr), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", urlStr), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved trace available fields", zap.String("searchText", searchText), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetLogsAvailableFields(ctx context.Context, searchText string) (json.RawMessage, error) {
	encodedSearchText := url.QueryEscape(searchText)
	urlStr := fmt.Sprintf("%s/api/v3/filter_suggestions?searchText=%s&dataSource=logs&existingFilter=e30", s.baseURL, encodedSearchText)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching logs available fields", zap.String("searchText", searchText))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", urlStr), zap.String("searchText", searchText), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", urlStr), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", urlStr), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved logs available fields", zap.String("searchText", searchText), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetMetricsAvailableFields(ctx context.Context, searchText string) (json.RawMessage, error) {
	encodedSearchText := url.QueryEscape(searchText)
	urlStr := fmt.Sprintf("%s/api/v3/autocomplete/aggregate_attributes?aggregateOperator=avg&searchText=%s&dataSource=metrics", s.baseURL, encodedSearchText)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching metrics available fields", zap.String("searchText", searchText))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", urlStr), zap.String("searchText", searchText), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", urlStr), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", urlStr), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved metrics available fields", zap.String("searchText", searchText), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetLogsFieldValues(ctx context.Context, fieldName string, searchText string) (json.RawMessage, error) {
	encodedFieldName := url.QueryEscape(fieldName)
	encodedSearchText := url.QueryEscape(searchText)
	urlStr := fmt.Sprintf("%s/api/v3/autocomplete/attribute_values?aggregateOperator=noop&dataSource=logs&aggregateAttribute=&attributeKey=%s&searchText=%s&filterAttributeKeyDataType=string&tagType=resource", s.baseURL, encodedFieldName, encodedSearchText)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching logs field values", zap.String("fieldName", fieldName), zap.String("searchText", searchText))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", urlStr), zap.String("fieldName", fieldName), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", urlStr), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", urlStr), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved logs field values", zap.String("fieldName", fieldName), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetMetricsFieldValues(ctx context.Context, fieldName string, searchText string) (json.RawMessage, error) {
	encodedFieldName := url.QueryEscape(fieldName)
	encodedSearchText := url.QueryEscape(searchText)
	urlStr := fmt.Sprintf("%s/api/v1/fields/keys?signal=metrics&metricName=%s&searchText=%s&fieldContext=&fieldDataType=&source=", s.baseURL, encodedFieldName, encodedSearchText)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentType, "application/json")
	req.Header.Set(SignozApiKey, s.apiKey)

	ctx, cancel := context.WithTimeout(ctx, 600*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	s.logger.Debug("Fetching metrics field values", zap.String("fieldName", fieldName), zap.String("searchText", searchText))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", urlStr), zap.String("fieldName", fieldName), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Failed to close response body", zap.Error(err))
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", urlStr), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", urlStr), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved metrics field values", zap.String("fieldName", fieldName), zap.Int("status", resp.StatusCode))
	return body, nil
}

func (s *SigNoz) GetTraceDetails(ctx context.Context, traceID string, includeSpans bool, startTime, endTime int64) (json.RawMessage, error) {
	if startTime == 0 || endTime == 0 {
		return nil, fmt.Errorf("start and end time parameters are required")
	}

	filterExpression := fmt.Sprintf("traceID = '%s'", traceID)
	limit := 1000

	queryPayload := types.BuildTracesQueryPayload(startTime, endTime, filterExpression, limit)
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

	limit := 1000
	queryPayload := types.BuildTracesQueryPayload(startTime, endTime, filterExpression, limit)
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
	limit := 1000
	queryPayload := types.BuildTracesQueryPayload(startTime, endTime, filterExpression, limit)
	queryJSON, err := json.Marshal(queryPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query payload: %w", err)
	}

	return s.QueryBuilderV5(ctx, queryJSON)
}

func (s *SigNoz) CreateDashboard(ctx context.Context, dashboard types.Dashboard) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/dashboards", s.baseURL)

	dashboardJSON, err := json.Marshal(dashboard)
	if err != nil {
		return nil, fmt.Errorf("marshal dashboard: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(dashboardJSON))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return body, nil
}

func (s *SigNoz) UpdateDashboard(ctx context.Context, id string, dashboard types.Dashboard) error {
	url := fmt.Sprintf("%s/api/v1/dashboards/%s", s.baseURL, id)

	dashboardJSON, err := json.Marshal(dashboard)
	if err != nil {
		return fmt.Errorf("marshal dashboard: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(dashboardJSON))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *SigNoz) DeleteDashboard(ctx context.Context, uuid string) error {
	url := fmt.Sprintf("%s/api/v1/dashboards/%s", s.baseURL, uuid)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *SigNoz) CreateSavedView(ctx context.Context, savedView types.SavedView) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/explorer/views", s.baseURL)

	savedViewJSON, err := json.Marshal(savedView)
	if err != nil {
		return nil, fmt.Errorf("marshal saved view: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(savedViewJSON))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) UpdateSavedView(ctx context.Context, viewID string, savedView types.SavedView) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/explorer/views/%s", s.baseURL, viewID)

	savedViewJSON, err := json.Marshal(savedView)
	if err != nil {
		return nil, fmt.Errorf("marshal saved view: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(savedViewJSON))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) DeleteSavedView(ctx context.Context, viewID string) error {
	url := fmt.Sprintf("%s/api/v1/explorer/views/%s", s.baseURL, viewID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *SigNoz) CreateAlertRule(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/rules", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UpdateAlertRule(ctx context.Context, ruleID string, body json.RawMessage) error {
	url := fmt.Sprintf("%s/api/v1/rules/%s", s.baseURL, ruleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SigNoz) DeleteAlertRule(ctx context.Context, ruleID string) error {
	url := fmt.Sprintf("%s/api/v1/rules/%s", s.baseURL, ruleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SigNoz) ListNotificationChannels(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/channels", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	s.logger.Debug("Fetching notification channels from SigNoz")

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved notification channels", zap.Int("status", resp.StatusCode))
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetNotificationChannel(ctx context.Context, channelID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/channels/%s", s.baseURL, channelID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	s.logger.Debug("Fetching notification channel details", zap.String("channelID", channelID))

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("channelID", channelID), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved notification channel", zap.String("channelID", channelID), zap.Int("status", resp.StatusCode))
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) CreateNotificationChannel(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/channels", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UpdateNotificationChannel(ctx context.Context, channelID string, body json.RawMessage) error {
	url := fmt.Sprintf("%s/api/v1/channels/%s", s.baseURL, channelID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SigNoz) DeleteNotificationChannel(ctx context.Context, channelID string) error {
	url := fmt.Sprintf("%s/api/v1/channels/%s", s.baseURL, channelID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SigNoz) ListDowntimeSchedules(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/downtime_schedules", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	s.logger.Debug("Fetching downtime schedules from SigNoz")

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved downtime schedules", zap.Int("status", resp.StatusCode))
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetDowntimeSchedule(ctx context.Context, scheduleID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/downtime_schedules/%s", s.baseURL, scheduleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	s.logger.Debug("Fetching downtime schedule details", zap.String("scheduleID", scheduleID))

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		s.logger.Error("HTTP request failed", zap.String("url", url), zap.String("scheduleID", scheduleID), zap.Error(err))
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("API request failed", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("response", string(body)))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.String("url", url), zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	s.logger.Debug("Successfully retrieved downtime schedule", zap.String("scheduleID", scheduleID), zap.Int("status", resp.StatusCode))
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) CreateDowntimeSchedule(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/downtime_schedules", s.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UpdateDowntimeSchedule(ctx context.Context, scheduleID string, body json.RawMessage) error {
	url := fmt.Sprintf("%s/api/v1/downtime_schedules/%s", s.baseURL, scheduleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *SigNoz) DeleteDowntimeSchedule(ctx context.Context, scheduleID string) error {
	url := fmt.Sprintf("%s/api/v1/downtime_schedules/%s", s.baseURL, scheduleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === Alert Route Policies ===

func (s *SigNoz) ListRoutePolicies(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/route_policies", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetRoutePolicy(ctx context.Context, policyID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/route_policies/%s", s.baseURL, policyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) CreateRoutePolicy(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/route_policies", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UpdateRoutePolicy(ctx context.Context, policyID string, body json.RawMessage) error {
	url := fmt.Sprintf("%s/api/v1/route_policies/%s", s.baseURL, policyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *SigNoz) DeleteRoutePolicy(ctx context.Context, policyID string) error {
	url := fmt.Sprintf("%s/api/v1/route_policies/%s", s.baseURL, policyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// === Dependency Graph ===

func (s *SigNoz) GetDependencyGraph(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/dependency_graph", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

// === TTL / Retention Settings ===

func (s *SigNoz) GetTTLSettings(ctx context.Context, signalType string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/settings/ttl?type=%s", s.baseURL, signalType)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) SetTTLSettings(ctx context.Context, signalType string, duration string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/settings/ttl?type=%s&duration=%s", s.baseURL, signalType, duration)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) GetTTLSettingsV2(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v2/settings/ttl", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) SetTTLSettingsV2(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v2/settings/ttl", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

// === Infra Metrics K8s ===

func (s *SigNoz) ListInfraResources(ctx context.Context, resourceType string, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/%s/list", s.baseURL, resourceType)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) GetInfraAttributeKeys(ctx context.Context, resourceType string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/%s/attribute_keys?dataSource=metrics", s.baseURL, resourceType)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetInfraAttributeValues(ctx context.Context, resourceType string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/%s/attribute_values?dataSource=metrics", s.baseURL, resourceType)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

// === Logs Pipelines ===

func (s *SigNoz) GetLogsPipelines(ctx context.Context, version string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/logs/pipelines/%s", s.baseURL, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) SaveLogsPipelines(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/logs/pipelines", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) PreviewLogsPipeline(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/logs/pipelines/preview", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

// === Integrations ===

func (s *SigNoz) ListIntegrations(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/integrations", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetIntegration(ctx context.Context, integrationID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/integrations/%s", s.baseURL, integrationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) InstallIntegration(ctx context.Context, integrationID string, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/integrations/install", s.baseURL)
	reqBody := map[string]interface{}{"integration_id": integrationID}
	if len(body) > 0 {
		var configMap map[string]interface{}
		if err := json.Unmarshal(body, &configMap); err == nil {
			for k, v := range configMap {
				reqBody[k] = v
			}
		}
	}
	mergedBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(mergedBody))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UninstallIntegration(ctx context.Context, integrationID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/integrations/uninstall", s.baseURL)
	reqBody, _ := json.Marshal(map[string]string{"integration_id": integrationID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) GetIntegrationConnectionStatus(ctx context.Context, integrationID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/integrations/%s/connection_status", s.baseURL, integrationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

// === Apdex Settings ===

func (s *SigNoz) GetApdexSettings(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/settings/apdex", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) SetApdexSettings(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/settings/apdex", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

// === User Management ===

func (s *SigNoz) ListUsers(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/user", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetUser(ctx context.Context, userID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/user/%s", s.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) UpdateUser(ctx context.Context, userID string, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/user/%s", s.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) DeleteUser(ctx context.Context, userID string) error {
	url := fmt.Sprintf("%s/api/v1/user/%s", s.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *SigNoz) ListInvites(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/invite", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) CreateInvite(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/invite", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) RevokeInvite(ctx context.Context, inviteID string) error {
	url := fmt.Sprintf("%s/api/v1/invite/%s", s.baseURL, inviteID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *SigNoz) ListPATs(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/pats", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) CreatePAT(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/pats", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UpdatePAT(ctx context.Context, patID string, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/pats/%s", s.baseURL, patID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) RevokePAT(ctx context.Context, patID string) error {
	url := fmt.Sprintf("%s/api/v1/pats/%s", s.baseURL, patID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// === Role Management ===

func (s *SigNoz) ListRoles(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/roles", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetRole(ctx context.Context, roleID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/roles/%s", s.baseURL, roleID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) CreateRole(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/roles", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UpdateRole(ctx context.Context, roleID string, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/roles/%s", s.baseURL, roleID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) DeleteRole(ctx context.Context, roleID string) error {
	url := fmt.Sprintf("%s/api/v1/roles/%s", s.baseURL, roleID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// === Cloud Integrations (AWS) ===

func (s *SigNoz) ListCloudAccounts(ctx context.Context, cloudProvider string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/cloud-integrations/%s/accounts", s.baseURL, cloudProvider)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) GetCloudAccount(ctx context.Context, cloudProvider string, accountID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/cloud-integrations/%s/accounts/%s/status", s.baseURL, cloudProvider, accountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

func (s *SigNoz) CreateCloudAccount(ctx context.Context, cloudProvider string, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/cloud-integrations/%s/accounts/generate-connection-url", s.baseURL, cloudProvider)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) UpdateCloudAccount(ctx context.Context, cloudProvider string, accountID string, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/cloud-integrations/%s/accounts/%s/config", s.baseURL, cloudProvider, accountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) DeleteCloudAccount(ctx context.Context, cloudProvider string, accountID string) error {
	url := fmt.Sprintf("%s/api/v1/cloud-integrations/%s/accounts/%s/disconnect", s.baseURL, cloudProvider, accountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (s *SigNoz) GetCloudAccountServices(ctx context.Context, cloudProvider string, accountID string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/cloud-integrations/%s/services", s.baseURL, cloudProvider)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(body) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return body, nil
}

// === Messaging Queues (Kafka) ===

func (s *SigNoz) GetKafkaConsumerLagOverview(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/messaging-queues/kafka/consumer-lag/consumer-details", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) GetKafkaPartitionLatency(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/messaging-queues/kafka/partition-latency/overview", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}

func (s *SigNoz) GetKafkaProducerOverview(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/api/v1/messaging-queues/kafka/topic-throughput/producer", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set(SignozApiKey, s.apiKey)
	req.Header.Set(ContentType, "application/json")
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req.WithContext(timeoutCtx))
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isHTMLResponse(respBody) {
		return nil, fmt.Errorf("endpoint returned HTML instead of JSON (route may not exist in this SigNoz version)")
	}
	return respBody, nil
}
