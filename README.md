# SigNoz MCP Server

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![MCP Version](https://img.shields.io/badge/MCP-0.37.0-orange.svg)](https://modelcontextprotocol.io)

> Extended fork of [SigNoz/signoz-mcp-server](https://github.com/SigNoz/signoz-mcp-server) — expanded from 25 read-only tools to 92 full CRUD tools.

A Model Context Protocol (MCP) server that provides comprehensive access to SigNoz observability data through AI assistants and LLMs. With **92 tools** covering full CRUD operations across 20+ API categories, this server enables natural language management of your entire SigNoz platform.

## 🚀 Features

**92 tools** across the following categories:

- **Metrics** — List and search metric keys
- **Alerts** — Full CRUD: list, get, create, update, delete alert rules + alert history
- **Dashboards** — Full CRUD: list, get, create, delete dashboards
- **Services** — List services, get top operations
- **Logs** — Saved log views, error logs, search by service, alert-related logs
- **Traces** — Search, details, error analysis, span hierarchy
- **Field Discovery** — Available fields and field values for traces, logs, and metrics
- **Query Builder** — Execute SigNoz Query Builder v5 queries
- **Saved Views** — CRUD for explorer saved views (logs/traces)
- **Notification Channels** — Full CRUD: webhook, Slack, PagerDuty, etc.
- **Downtime Schedules** — Full CRUD for planned maintenance windows
- **Route Policies** — Full CRUD for alert routing policies
- **Dependency Graph** — Service dependency visualization
- **TTL Settings** — Get/set data retention (v1 and v2)
- **Infrastructure Monitoring** — List hosts, pods, nodes, namespaces, clusters, etc. with attribute discovery
- **Logs Pipelines** — Get, preview, and save log processing pipelines
- **Integrations** — List, get, install, uninstall integrations + connection status
- **Apdex Settings** — Get/set application performance index thresholds
- **User Management** — List, get, update, delete users + invite management
- **Personal Access Tokens** — List, create, update, revoke PATs
- **Role Management** — Full CRUD for custom roles (Enterprise)
- **Cloud Integrations** — Full CRUD for AWS/GCP/Azure cloud accounts + service discovery
- **Messaging Queues** — Kafka consumer lag, partition latency, producer throughput

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Client    │───▶│  MCP Server      │───▶│   SigNoz API    │
│  (AI Assistant) │    │  (Go)            │    │  (Observability)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   Tool Handlers  │
                       │  (HTTP Client)   │
                       └──────────────────┘
```

### Core Components

- **MCP Server**: Handles MCP protocol communication
- **Tool Handlers**: Register and manage available tools
- **SigNoz Client**: HTTP client for SigNoz API interactions
- **Configuration**: Environment-based configuration management
- **Logging**: Structured logging with Zap

## 🧰 Usage

Use this mcp-server with MCP-compatible clients like Claude Desktop and Cursor.

### Claude Desktop

1. Build or locate the binary path for `signoz-mcp-server` (for example: `.../signoz-mcp-server/bin/signoz-mcp-server`).
2. Goto Claude -> Settings -> Developer -> Local MCP Server click on `edit config`
3. Edit `claude_desktop_config.json` Add shown config with your signoz url, api key and path to signoz-mcp-server binary.

```json
{
    "mcpServers": {
        "signoz": {
            "command": "/absolute/path/to/signoz-mcp-server/bin/signoz-mcp-server",
            "args": [],
            "env": {
                "SIGNOZ_URL": "https://your-signoz-instance.com",
                "SIGNOZ_API_KEY": "your-api-key-here",
                "LOG_LEVEL": "info"
            }
        }
    }
}
```

4. Restart Claude Desktop. You should see the `signoz` server load in the developer console and its tools become available.

Notes:

- Replace the `command` path with your actual binary location.

### Cursor

Option A — GUI:

- Open Cursor → Settings → Cursor Settings → Tool & Integrations → `+` New MCP Server

Option B — Project config file:
Create `.cursor/mcp.json` in your project root:

For Both options use same json struct

```json
{
    "mcpServers": {
        "signoz": {
            "command": "/absolute/path/to/signoz-mcp-server/bin/signoz-mcp-server",
            "args": [],
            "env": {
                "SIGNOZ_URL": "https://your-signoz-instance.com",
                "SIGNOZ_API_KEY": "your-api-key-here",
                "LOG_LEVEL": "info"
            }
        }
    }
}
```

Once added, restart Cursor to use the SigNoz tools.

### HTTP based self hosted mcp server

### Claude Desktop

1. Build and run signoz-mcp-server with envs
    - SIGNOZ_URL=signoz_url SIGNOZ_API_KEY=signoz_apikey TRANSPORT_MODE=http MCP_SERVER_PORT=8000 LOG_LEVEL=log_level ./signoz-mcp-server
    - or use docker-compose
2. Goto Claude -> Settings -> Developer -> Local MCP Server click on `edit config`
3. Edit `claude_desktop_config.json` Add shown config with your signoz url, api key and path to signoz-mcp-server binary.

```json
{
    "mcpServers": {
        "signoz": {
            "url": "http://localhost:8000/mcp",
            "headers": {
                "Authorization": "Bearer your-api-key-here"
            }
        }
    }
}
```

**Note:** You can pass the SigNoz API key either as:

- An environment variable (`SIGNOZ_API_KEY`) when starting the server, or
- Via the `Authorization` header in the client configuration as shown above

4. Restart Claude Desktop. You should see the `signoz` server load in the developer console and its tools become available.

### Cursor

Build and run signoz-mcp-server with envs - SIGNOZ_URL=signoz_url SIGNOZ_API_KEY=signoz_apikey TRANSPORT_MODE=http MCP_SERVER_PORT=8000 LOG_LEVEL=log_level ./signoz-mcp-server - or use docker-compose

Option A — GUI:

- Open Cursor → Settings → Cursor Settings → Tool & Integrations → `+` New MCP Server

Option B — Project config file:
Create `.cursor/mcp.json` in your project root:

For Both options use same json struct

```json
{
    "mcpServers": {
        "signoz": {
            "url": "http://localhost:8000/mcp",
            "headers": {
                "Authorization": "Bearer signoz-api-key-here"
            }
        }
    }
}
```

**Note:** You can pass the SigNoz API key either as:

- An environment variable (`SIGNOZ_API_KEY`) when starting the server, or
- Via the `Authorization` header in the client configuration as shown above

**Note:** By default, the server logs at `info` level. If you need detailed debugging information, set `LOG_LEVEL=debug` in your environment. For production use, consider using `LOG_LEVEL=warn` to reduce log verbosity.

## 🛠️ Development Guide

### Prerequisites

- Go 1.25 or higher
- SigNoz instance with API access
- Valid SigNoz API key

### Project Structure

```
signoz-mcp-server/
├── cmd/server/           # Main application entry point
├── internal/
│   ├── client/          # SigNoz API client (88 methods)
│   ├── config/          # Configuration management
│   ├── handler/tools/   # MCP tool implementations (92 tools)
│   ├── logger/          # Logging utilities
│   └── mcp-server/      # MCP server core
├── pkg/types/           # Shared type definitions
├── go.mod               # Go module dependencies
├── Makefile             # Build automation
└── README.md
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/FeelKyoun/signoz-mcp-server.git
cd signoz-mcp-server

# Build the binary
make build

# Or build directly with Go
go build -o bin/signoz-mcp-server ./cmd/server/
```

### Configuration

Set the following environment variables:

```bash

export SIGNOZ_URL="https://your-signoz-instance.com"
export SIGNOZ_API_KEY="your-api-key-here"
export LOG_LEVEL="info"  # Optional: debug, info, error (default: info)
```

In SigNoz Cloud, SIGNOZ_URL is typically - https://ingest.<region>.signoz.cloud

You can access API Key by going to Settings -> Workspace Settings -> API Key in SigNoz UI

### Running the Server

```bash
# Run the built binary
./bin/signoz-mcp-server
```

### Development Workflow

1. **Add New Tools**: Implement in `internal/handler/tools/`
2. **Extend Client**: Add methods to `internal/client/client.go`
3. **Register Tools**: Add to appropriate handler registration
4. **Test**: Use MCP client to verify functionality

## 📖 User Guide

### For AI Assistants & LLMs

The MCP server provides 92 tools that can be used through natural language:

#### Metrics & Services

```
"Show me all available metrics"
"Search for CPU related metrics"
"List all services from the last 6 hours"
"What are the top operations for the paymentservice?"
```

#### Alert Management

```
"List all active alerts"
"Create an alert for high CPU usage on the payment service"
"Delete alert rule abc123"
"Show me the history for alert rule abc123 from the last 6 hours"
```

#### Dashboard Management

```
"List all dashboards"
"Create a dashboard named 'API Performance' with latency widgets"
"Show me the Host Metrics dashboard details"
```

#### Log & Trace Analysis

```
"Show me error logs for the paymentservice from the last hour"
"Search traces for the checkout service with errors"
"Get the span hierarchy for trace xyz789"
"Create a saved view for error logs filtered by payment service"
```

#### Notification & Routing

```
"Set up a Slack notification channel for alerts"
"List all notification channels"
"Create a route policy to send INFO alerts to the dev channel"
```

#### Infrastructure & Integrations

```
"Show me all hosts and their CPU usage"
"List all pods in the production namespace"
"Install the AWS ElastiCache Redis integration"
"What's the Kafka consumer lag for the orders topic?"
```

#### Settings & Administration

```
"Set the data retention for logs to 30 days"
"Create a downtime schedule for weekend maintenance"
"List all users and their roles"
"Create a personal access token with VIEWER role"
```

### Tool Reference (92 Tools)

#### Metrics (2)

| Tool | Description |
|------|-------------|
| `signoz_list_metric_keys` | List all available metric keys |
| `signoz_search_metric_by_text` | Search metrics by text pattern |

#### Alerts (6)

| Tool | Description |
|------|-------------|
| `signoz_list_alerts` | List all alert rules with status |
| `signoz_get_alert` | Get alert rule details by ID |
| `signoz_get_alert_history` | Get alert history timeline with pagination |
| `signoz_create_alert_rule` | Create a new alert rule with conditions, channels, and labels |
| `signoz_update_alert_rule` | Update an existing alert rule |
| `signoz_delete_alert_rule` | Delete an alert rule |

#### Dashboards (4)

| Tool | Description |
|------|-------------|
| `signoz_list_dashboards` | List dashboards with summaries (name, UUID, tags) |
| `signoz_get_dashboard` | Get complete dashboard configuration by UUID |
| `signoz_create_dashboard` | Create a new dashboard with title, layout, and widgets |
| `signoz_delete_dashboard` | Delete a dashboard by UUID |

#### Services (2)

| Tool | Description |
|------|-------------|
| `signoz_list_services` | List all services within a time range |
| `signoz_get_service_top_operations` | Get top operations for a specific service |

#### Logs (5)

| Tool | Description |
|------|-------------|
| `signoz_list_log_views` | List all saved log views with pagination |
| `signoz_get_log_view` | Get full details of a saved log view |
| `signoz_get_logs_for_alert` | Get logs related to a specific alert |
| `signoz_get_error_logs` | Get ERROR/FATAL logs within a time range |
| `signoz_search_logs_by_service` | Search logs by service, severity, and text |

#### Traces (4)

| Tool | Description |
|------|-------------|
| `signoz_search_traces_by_service` | Search traces by service, operation, duration, error status |
| `signoz_get_trace_details` | Get trace details including all spans |
| `signoz_get_trace_error_analysis` | Analyze error patterns in traces |
| `signoz_get_trace_span_hierarchy` | Get trace span parent-child relationships |

#### Field Discovery (6)

| Tool | Description |
|------|-------------|
| `signoz_get_trace_field_values` | Get available values for a trace field |
| `signoz_get_logs_field_values` | Get available values for a log field |
| `signoz_get_metrics_field_values` | Get available values for a metric field |
| `signoz_get_trace_available_fields` | List available trace field names |
| `signoz_get_logs_available_fields` | List available log field names |
| `signoz_get_metrics_available_fields` | List available metric field names |

#### Query Builder (1)

| Tool | Description |
|------|-------------|
| `signoz_execute_builder_query` | Execute a SigNoz Query Builder v5 query ([docs](https://signoz.io/docs/userguide/query-builder-v5/)) |

#### Saved Views (3)

| Tool | Description |
|------|-------------|
| `signoz_create_saved_view` | Create a saved view for logs/traces explorer |
| `signoz_update_saved_view` | Update an existing saved view |
| `signoz_delete_saved_view` | Delete a saved view |

#### Notification Channels (5)

| Tool | Description |
|------|-------------|
| `signoz_list_notification_channels` | List all notification channels |
| `signoz_get_notification_channel` | Get channel details by ID |
| `signoz_create_notification_channel` | Create a channel (webhook, Slack, PagerDuty, etc.) |
| `signoz_update_notification_channel` | Update channel configuration |
| `signoz_delete_notification_channel` | Delete a notification channel |

#### Downtime Schedules (5)

| Tool | Description |
|------|-------------|
| `signoz_list_downtime_schedules` | List all planned maintenance schedules |
| `signoz_get_downtime_schedule` | Get schedule details by ID |
| `signoz_create_downtime_schedule` | Create a downtime schedule with recurrence |
| `signoz_update_downtime_schedule` | Update an existing schedule |
| `signoz_delete_downtime_schedule` | Delete a downtime schedule |

#### Route Policies (5)

| Tool | Description |
|------|-------------|
| `signoz_list_route_policies` | List all alert routing policies |
| `signoz_get_route_policy` | Get policy details by ID |
| `signoz_create_route_policy` | Create a routing policy with expression and channels |
| `signoz_update_route_policy` | Update an existing routing policy |
| `signoz_delete_route_policy` | Delete a routing policy |

#### Dependency Graph (1)

| Tool | Description |
|------|-------------|
| `signoz_get_dependency_graph` | Get service dependency graph for a time range |

#### TTL Settings (4)

| Tool | Description |
|------|-------------|
| `signoz_get_ttl_settings` | Get data retention settings (v1) |
| `signoz_set_ttl_settings` | Set data retention by type: traces, logs, metrics (v1) |
| `signoz_get_ttl_settings_v2` | Get data retention settings (v2) |
| `signoz_set_ttl_settings_v2` | Set data retention settings (v2) |

#### Infrastructure Monitoring (3)

| Tool | Description |
|------|-------------|
| `signoz_list_infra_resources` | List infra resources: hosts, pods, nodes, namespaces, clusters, deployments, etc. |
| `signoz_get_infra_attribute_keys` | Get attribute keys for a resource type |
| `signoz_get_infra_attribute_values` | Get attribute values for a resource type |

#### Logs Pipelines (3)

| Tool | Description |
|------|-------------|
| `signoz_get_logs_pipelines` | Get log processing pipeline configuration |
| `signoz_preview_logs_pipeline` | Preview pipeline effect on sample logs without saving |
| `signoz_save_logs_pipelines` | Save log processing pipeline configuration |

#### Integrations (5)

| Tool | Description |
|------|-------------|
| `signoz_list_integrations` | List all available integrations |
| `signoz_get_integration` | Get integration details and configuration |
| `signoz_get_integration_connection_status` | Check integration connection status |
| `signoz_install_integration` | Install an integration with configuration |
| `signoz_uninstall_integration` | Uninstall an integration |

#### Apdex Settings (2)

| Tool | Description |
|------|-------------|
| `signoz_get_apdex_settings` | Get application performance index settings |
| `signoz_set_apdex_settings` | Set apdex threshold for a service |

#### User Management (7)

| Tool | Description |
|------|-------------|
| `signoz_list_users` | List all users |
| `signoz_get_user` | Get user details by ID |
| `signoz_update_user` | Update user name or role |
| `signoz_delete_user` | Delete a user |
| `signoz_list_invites` | List pending invitations |
| `signoz_create_invite` | Invite a new user with role |
| `signoz_revoke_invite` | Revoke a pending invitation |

#### Personal Access Tokens (4)

| Tool | Description |
|------|-------------|
| `signoz_list_pats` | List all personal access tokens |
| `signoz_create_pat` | Create a PAT with name, role, and expiration |
| `signoz_update_pat` | Update PAT name or role |
| `signoz_revoke_pat` | Revoke a personal access token |

#### Role Management (5) — Enterprise

> Requires a valid SigNoz Enterprise license.

| Tool | Description |
|------|-------------|
| `signoz_list_roles` | List all custom roles |
| `signoz_get_role` | Get role details by ID |
| `signoz_create_role` | Create a custom role with permissions |
| `signoz_update_role` | Update role permissions |
| `signoz_delete_role` | Delete a custom role |

#### Cloud Integrations (6)

| Tool | Description |
|------|-------------|
| `signoz_list_cloud_accounts` | List cloud accounts for a provider (AWS/GCP/Azure) |
| `signoz_get_cloud_account` | Get cloud account status |
| `signoz_create_cloud_account` | Connect a new cloud account |
| `signoz_update_cloud_account` | Update cloud account configuration |
| `signoz_delete_cloud_account` | Disconnect a cloud account |
| `signoz_get_cloud_account_services` | List available cloud services for a provider |

#### Messaging Queues — Kafka (3)

| Tool | Description |
|------|-------------|
| `signoz_get_kafka_consumer_lag` | Get consumer lag details for a topic/consumer group |
| `signoz_get_kafka_partition_latency` | Get partition-level latency for a topic |
| `signoz_get_kafka_producer_overview` | Get producer throughput for a topic |

### Time Format

Most tools support flexible time parameters:

#### Recommended: Time Ranges

Use the `timeRange` parameter with formats:

- `'30m'` - Last 30 minutes
- `'2h'` - Last 2 hours
- `'6h'` - Last 6 hours
- `'2d'` - Last 2 days
- `'7d'` - Last 7 days

The `timeRange` parameter automatically calculates the time window from now backwards. If not specified, most tools default to the last 6 hours. You can also specify time in milliseconds and nanoseconds

### Response Format

All tools return JSON responses that are optimized for LLM consumption:

- **List operations**: Return summaries to avoid overwhelming responses
- **Detail operations**: Return complete data when specific information is requested
- **Error handling**: Structured error messages for debugging

## 🔧 Configuration & Deployment

### Environment Variables

| Variable          | Description                                                                    | Required                            |
| ----------------- | ------------------------------------------------------------------------------ | ----------------------------------- |
| `SIGNOZ_URL`      | SigNoz instance URL                                                            | Yes                                 |
| `SIGNOZ_API_KEY`  | SigNoz API key (get from Settings → Workspace Settings → API Key in SigNoz UI) | Yes                                 |
| `LOG_LEVEL`       | Logging level: `info`(default), `debug`, `warn`, `error`                       | No                                  |
| `TRANSPORT_MODE`  | MCP transport mode: `stdio`(default) or `http`                                 | No                                  |
| `MCP_SERVER_PORT` | Port for HTTP transport mode                                                   | Yes only when `TRANSPORT_MODE=http` |

## Claude Desktop Extension Setup

### 🧱 Building the Claude Extension Bundle

Ensure **Node.js** is installed on your system.
For details about the MCPB CLI, see [Anthropic MCPB GitHub repository](https://github.com/anthropics/mcpb).

From the repository root, run:

```bash
make bundle
```

This command builds platform binaries (macOS and Windows), copies manifest and assets, installs the MCPB CLI (`@anthropic-ai/mcpb`), and packages everything into a Claude-compatible `.mcpb` bundle.

### 💻 Installing in Claude Desktop

1. Open **Claude Desktop → Settings → Developer → Edit Config -> Add bundle.mcpb**
2. Select the generated bundle:

    ```
    ./bundle/bundle.mcpb
    ```

3. Provide your SigNoz configuration:
    - `SIGNOZ_URL`: URL of your SigNoz instance
    - `SIGNOZ_API_KEY`: API key from **SigNoz UI → Settings → Workspace Settings → API Key**
    - `LOG_LEVEL`: Optional (`info`, `debug`, or `warn`)

Restart Claude Desktop and it will then automatically start the SigNoz MCP Server and register its tools.

---

## 🤝 Contributing

Contributions are welcome! This is a fork — feel free to open issues or pull requests on [this repository](https://github.com/FeelKyoun/signoz-mcp-server).

### Development Setup

1. Clone the repository
2. Create a feature branch
3. Make your changes
4. Run `go build ./...` to verify
5. Submit a pull request

### Code Style

- Follow Go best practices
- Use meaningful variable names
- Ensure proper error handling
- Match existing patterns in `client.go` and `handler.go`

**Made with ❤️ for the observability community**
