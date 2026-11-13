package output

import (
	"time"

	"github.com/projectdiscovery/katana/pkg/navigation"
)

// Result of the crawling
type Result struct {
	Timestamp time.Time            `json:"timestamp,omitempty"`
	Request   *navigation.Request  `json:"request,omitempty"`
	Response  *navigation.Response `json:"response,omitempty"`
	Error     string               `json:"error,omitempty"`
	// SkipReason carries the scope.Reason code (e.g. scope_out_of_bound,
	// scope_path_filtered, scope_depth_exceeded) when the request was
	// intercepted by a scope check instead of being visited. Empty for
	// normally crawled results.
	SkipReason string `json:"skip_reason,omitempty"`
}

// HasResponse checks if the result has a valid response
func (r *Result) HasResponse() bool {
	return r.Response != nil && r.Response.Resp != nil
}
