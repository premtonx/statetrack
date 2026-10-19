package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AnnotationClient talks to Grafana's annotation API.
//
// It exists so both seeders can keep the dashboard's flags in step with the
// database without duplicating HTTP plumbing. The important property is not the
// transport but the contract its callers follow: an annotation is always pushed
// *after* the events table has been rewritten, carrying the UUID PostgreSQL
// actually stored. A flag whose link points at a deleted row is the "Failed to
// load event" 404 this type exists to prevent.
type AnnotationClient struct {
	base   string
	user   string
	pass   string
	token  string
	client *http.Client
}

// NewAnnotationClient builds a client for a Grafana instance.
//
// `token` is optional: with it the client authenticates as a service account
// (how a live deployment annotates), without it as the admin user (how the demo
// seeds). Both paths are exercised by the seeders.
func NewAnnotationClient(base, user, pass, token string, timeout time.Duration) *AnnotationClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &AnnotationClient{
		base:   strings.TrimRight(base, "/"),
		user:   user,
		pass:   pass,
		token:  token,
		client: &http.Client{Timeout: timeout},
	}
}

// BaseURL reports the instance this client points at.
func (c *AnnotationClient) BaseURL() string { return c.base }

// Health reports whether the instance answers, so a caller can decide to skip
// annotation syncing rather than fail an otherwise successful seed.
func (c *AnnotationClient) Health(ctx context.Context) error {
	var out struct {
		Database string `json:"database"`
	}
	return c.do(ctx, http.MethodGet, "/api/health", nil, &out)
}

// Purge removes every annotation StateTrack owns inside the window and returns
// how many were deleted.
//
// Two selectors, unioned, because either alone leaves stale flags behind:
//
//   - the `statetrack` tag, which both the seeder and the live dispatcher sets;
//   - any annotation whose text contains a `/events/` link, which catches flags
//     written by older builds before the tag existed.
//
// The window is what keeps this safe to run against a real Grafana: only
// annotations overlapping [from, now+48h] are considered, and only ones the
// selectors positively identify as StateTrack's. An unrelated team's release
// annotation has neither the tag nor the link.
//
// Deleting is done id-by-id from the list response rather than with a bulk
// DELETE, because Grafana's bulk endpoint takes a query — not the same filter
// the list accepts — and a mismatch there would silently delete the wrong rows.
func (c *AnnotationClient) Purge(ctx context.Context, from time.Time) (int, error) {
	seen := map[int64]bool{}
	var ids []int64

	collect := func(query string) error {
		var rows []struct {
			ID   int64  `json:"id"`
			Text string `json:"text"`
		}
		if err := c.do(ctx, http.MethodGet, query, nil, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			if seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
		return nil
	}

	window := fmt.Sprintf("from=%d&to=%d&limit=500",
		from.UnixMilli(), time.Now().Add(48*time.Hour).UnixMilli())

	// 1. By tag.
	if err := collect("/api/annotations?tags=" + url.QueryEscape(SeedTag) + "&" + window); err != nil {
		return 0, err
	}
	// 2. By text: a wider net for flags predating the tag, filtered locally
	//    below so a page of unrelated annotations never gets deleted wholesale.
	var recent []struct {
		ID   int64  `json:"id"`
		Text string `json:"text"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/annotations?"+window, nil, &recent); err != nil {
		return 0, err
	}
	for _, r := range recent {
		if seen[r.ID] || !strings.Contains(r.Text, "/events/") {
			continue
		}
		seen[r.ID] = true
		ids = append(ids, r.ID)
	}

	removed := 0
	for _, id := range ids {
		if err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/annotations/%d", id), nil, nil); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// Create pushes one annotation and returns Grafana's id for it.
func (c *AnnotationClient) Create(ctx context.Context, ann Annotation) (int64, error) {
	var out struct {
		ID      int64  `json:"id"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/annotations", ann, &out); err != nil {
		return 0, err
	}
	if out.ID == 0 {
		return 0, fmt.Errorf("grafana accepted the annotation but returned no id (%s)", out.Message)
	}
	return out.ID, nil
}

func (c *AnnotationClient) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch {
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	case c.user != "":
		req.SetBasicAuth(c.user, c.pass)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("%s %s: %s: %s", method, path, res.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}
