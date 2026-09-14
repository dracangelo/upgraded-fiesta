package api

import _ "embed"

// dashboardHTML is a deterministic production bundle generated from the JSX
// source. It contains no runtime CDN, font, or in-browser compiler dependency.
//
//go:embed dashboard_dist.html
var dashboardHTML string
