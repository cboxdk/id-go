package cboxid

import "strings"

// apiEndpoint is where one of the SDK's own API calls goes, and whether that is the /v1
// API.
//
// Without Config.APIURL nothing changes: {Issuer}/api/v1{legacyPath}, the environment's
// own host with today's path. With it: {APIURL}/v1{v1Path}. Both paths start with a slash.
func (c *Client) apiEndpoint(v1Path, legacyPath string) (string, bool) {
	api := strings.TrimRight(strings.TrimSpace(c.cfg.APIURL), "/")
	if api == "" {
		return strings.TrimRight(c.cfg.Issuer, "/") + "/api/v1" + legacyPath, false
	}

	// https://api.cboxid.com and https://api.cboxid.com/v1 are the same setting.
	api = strings.TrimSuffix(api, "/v1")

	return api + "/v1" + v1Path, true
}
