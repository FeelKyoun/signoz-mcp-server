package types

import "encoding/json"

type SavedView struct {
	Name           string          `json:"name" jsonschema:"required" jsonschema_extras:"description=User-defined label for the saved view."`
	Category       string          `json:"category,omitempty" jsonschema_extras:"description=Classification of the view."`
	SourcePage     string          `json:"sourcePage" jsonschema:"required" jsonschema_extras:"description=Where the view was created: logs or traces."`
	Tags           []string        `json:"tags,omitempty" jsonschema_extras:"description=Tags for organization."`
	CompositeQuery json.RawMessage `json:"compositeQuery" jsonschema:"required" jsonschema_extras:"description=The query/filter configuration as a JSON object. Use signoz_get_log_view to see examples of existing view query structures."`
	ExtraData      string          `json:"extraData,omitempty" jsonschema_extras:"description=Additional frontend-specific JSON data."`
}

type UpdateSavedViewInput struct {
	ViewID    string    `json:"viewId" jsonschema:"required" jsonschema_extras:"description=UUID of the saved view to update. Use signoz_list_log_views to find view IDs."`
	SavedView SavedView `json:"savedView" jsonschema:"required" jsonschema_extras:"description=Complete saved view configuration representing the post-update state."`
}
