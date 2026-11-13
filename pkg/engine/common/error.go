package common

import "errors"

// Sentinel errors attached to output.Results when an intercepted URL is
// written out (e.g. with -display-out-scope or when MaxDepth is reached). The
// machine-readable reason code lives on output.Result.SkipReason.
var ErrOutOfScope = errors.New("out of scope")
var ErrMaxDepthReached = errors.New("max depth reached")
