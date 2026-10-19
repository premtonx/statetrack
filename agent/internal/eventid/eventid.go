// Package eventid generates time-sortable event IDs (UUIDv7).
package eventid

import "github.com/google/uuid"

// New returns a new UUIDv7 string.
func New() string {
	return uuid.Must(uuid.NewV7()).String()
}
