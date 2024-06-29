package sigma

import (
	"github.com/seacurity/current/internal/sigma/condition"
	"github.com/seacurity/current/internal/sigma/search"
)

type Detection struct {
	Searches  map[string][]search.Searches `yaml:",inline,omitempty"`
	TimeFrame string                       `yaml:",omitempty"`
	Condition condition.Condition          `yaml:",omitempty"`
}
