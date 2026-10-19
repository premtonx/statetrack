// Package webui embeds the production React console so the server binary is a
// single deployable artifact.
//
// The Docker build copies `web/dist` over `dist/` before compiling, which is
// what makes `docker run` serve the console and the API from the same origin
// without an nginx sidecar (and therefore without CORS or a second TLS terminator
// to configure).
//
// A `go build` from a fresh checkout has no built console: `dist/` holds only a
// README, because committing a built bundle would rot against `web/src`. That
// still has to compile, so the embed covers both the directory and a standalone
// `placeholder.html`, and Handler() serves the placeholder until a real build is
// staged. `//go:embed all:dist` alone would fail the build with "no matching
// files found" in exactly that checkout.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

//go:embed placeholder.html
var placeholder []byte

// FS returns the embedded console rooted at the dist directory.
func FS() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}

// Available reports whether a real build (rather than the checkout placeholder)
// is embedded. The server logs this at startup so an operator who built the Go
// binary by hand knows why the console looks like a stub.
func Available() bool {
	body, err := embedded.ReadFile("dist/index.html")
	if err != nil {
		return false
	}
	return !strings.Contains(string(body), `id="statetrack-placeholder"`)
}

// Handler serves the console with SPA fallback: every path that is not a real
// asset returns index.html so client-side routes like /servers and /drift work
// on a hard refresh or a deep link from Grafana.
//
// API routes are matched by the caller before this handler, so a mistyped
// /api/... path still 404s instead of silently returning HTML that the console
// would then fail to parse as JSON.
func Handler() (http.Handler, error) {
	root, err := FS()
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(root, "index.html")
	if err != nil {
		// No console was staged into the image. Serving the explainer beats a
		// 404 on `/` for someone who built the binary by hand.
		index = placeholder
	}
	fileServer := http.FileServer(http.FS(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" {
			if f, err := root.Open(name); err == nil {
				info, statErr := f.Stat()
				_ = f.Close()
				if statErr == nil && !info.IsDir() {
					// Hashed asset filenames are immutable, so they are the one
					// thing worth a long cache lifetime.
					if strings.HasPrefix(name, "assets/") {
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					fileServer.ServeHTTP(w, r)
					return
				}
			}
		}

		// Anything else is a client route (or a stale asset hash after an
		// upgrade); index.html lets the SPA router decide, and a stale hashed
		// asset correctly re-fetches the shell instead of 404ing the page.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	}), nil
}
