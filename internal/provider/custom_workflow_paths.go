package provider

import (
	"fmt"
	"path"
	"strings"
)

// customWorkflowPathProblem explains why a custom_workflow_paths entry is
// rejected, or returns "" when it is valid. It follows the API's rules (relative,
// inside the repository) and also requires the cleaned form the API stores, so
// state and the API never disagree on how a path is written.
func customWorkflowPathProblem(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return "custom_workflow_paths entries cannot be empty"
	}
	if strings.HasPrefix(trimmed, "/") {
		return fmt.Sprintf("custom_workflow_paths entry %q must be relative to the repository root, without a leading '/'", p)
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "." {
		return fmt.Sprintf("custom_workflow_paths entry %q must name a folder, not the repository root", p)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Sprintf("custom_workflow_paths entry %q must stay inside the repository", p)
	}
	if cleaned == ".github/workflows" {
		return "custom_workflow_paths should not list .github/workflows, it is always included"
	}
	if cleaned != p {
		return fmt.Sprintf("custom_workflow_paths entry %q must be written as %q", p, cleaned)
	}
	return ""
}
