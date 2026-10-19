This directory is the //go:embed target for the production React console.

It is committed only so `go build` from a fresh checkout compiles: `//go:embed
all:dist` fails outright when the directory does not exist, which would break
`go build ./server/...` for anyone who cloned the repo and has not run a web
build yet.

`web/dist` is copied over this directory by the Docker build and by
`scripts/release.sh`. Until then, the server serves `placeholder.html` (a page
explaining how to build the console) and reports `EmbeddedUI: false`.
