package source

import (
	"context"

	"github.com/enel1221/GroupBridge/internal/model"
)

// Source returns current identity state. Events are deliberately not modeled:
// they are hints that cause callers to fetch a fresh snapshot.
type Source interface {
	ListGroups(context.Context) ([]model.Group, error)
}
