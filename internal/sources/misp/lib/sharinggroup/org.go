package sharinggroup

import (
	"github.com/seacurity/current/internal/sources/misp/lib/organisation"
)

type Org struct {
	ID             string           `json:",omitempty"`
	SharingGroupId string           `json:"sharing_group_id,omitempty"`
	OrgID          string           `json:",omitempty"`
	Extend         bool             `json:",omitempty"`
	Organisation   organisation.Org `json:",omitempty"`
}
