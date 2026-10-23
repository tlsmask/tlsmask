package proxy

import (
	"net/http"
	"sort"
	"strings"
)

var chromeHeaderOrder = []string{
	"content-length",
	"pragma",
	"cache-control",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"upgrade-insecure-requests",
	"user-agent",
	"content-type",
	"accept",
	"origin",
	"x-requested-with",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-user",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"accept-language",
	"cookie",
	"priority",
}

var chromeHeaderRank = func() map[string]int {
	rank := make(map[string]int, len(chromeHeaderOrder))
	for i, name := range chromeHeaderOrder {
		rank[name] = i
	}
	return rank
}()

func stableHeaderOrder(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		lower := strings.ToLower(name)
		if hopByHopHeaders[lower] || lower == "host" || lower == "content-length" {
			continue
		}
		names = append(names, lower)
	}

	sort.Slice(names, func(i, j int) bool {
		ri, iKnown := chromeHeaderRank[names[i]]
		rj, jKnown := chromeHeaderRank[names[j]]
		switch {
		case iKnown && jKnown:
			return ri < rj
		case iKnown != jKnown:
			return iKnown
		default:
			return names[i] < names[j]
		}
	})
	return names
}
