package reporting

import (
	"encoding/json"
	"fmt"

	"enumscan/internal/models"
)

type BloodHoundUser struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	Name             string `json:"Name"`
	PrimaryGroupSID  string `json:"PrimaryGroupSID"`
	DontReqPreAuth   bool   `json:"DontReqPreAuth"`
}

type BloodHoundGraph struct {
	Users []BloodHoundUser `json:"users"`
}

func ExportBloodHoundJSON(assets []models.Asset) ([]byte, error) {
	var users []BloodHoundUser

	for i, asset := range assets {
		if asset.Type == "ldap_naming_context" || asset.Type == "active_directory_domain" {
			u := BloodHoundUser{
				ObjectIdentifier: fmt.Sprintf("S-1-5-21-3623811015-3361044348-30300820-%d", 1000+i),
				Name:             asset.Value,
				PrimaryGroupSID:  "S-1-5-21-3623811015-3361044348-30300820-513",
				DontReqPreAuth:   true,
			}
			users = append(users, u)
		}
	}

	graph := BloodHoundGraph{Users: users}
	return json.MarshalIndent(graph, "", "  ")
}
