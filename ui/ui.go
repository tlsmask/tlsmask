package ui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"path"
)

//go:embed index.html app.css app.js logo.png mark.png
var files embed.FS

type Asset struct {
	Body        []byte
	ContentType string
	ETag        string
}

var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".png":  "image/png",
}

func Load(name string) (Asset, error) {
	body, err := files.ReadFile(name)
	if err != nil {
		return Asset{}, err
	}
	sum := sha256.Sum256(body)
	return Asset{
		Body:        body,
		ContentType: contentTypes[path.Ext(name)],
		ETag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
	}, nil
}

func (a Asset) Serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", a.ETag)
	if r.Header.Get("If-None-Match") == a.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", a.ContentType)
	w.Write(a.Body)
}
