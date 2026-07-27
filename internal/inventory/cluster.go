package inventory

import (
	"strings"

	"enumscan/internal/models"
)

type HostCluster struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ClusterType string  `json:"cluster_type"`
	Members    []string `json:"members"`
}

type HostClusterer struct{}

func NewHostClusterer() *HostClusterer {
	return &HostClusterer{}
}

func (hc *HostClusterer) ClusterAssets(assets []models.InventoryAsset) []HostCluster {
	clusters := make(map[string][]string)

	for _, a := range assets {
		key := "subnet:other"
		if strings.Contains(a.Value, ".") {
			parts := strings.Split(a.Value, ".")
			if len(parts) == 4 {
				key = "subnet:" + parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
			}
		} else if strings.Contains(a.Value, ":") {
			key = "subnet:ipv6_group"
		} else if strings.Contains(a.Value, "example.com") {
			key = "domain:example.com"
		}

		clusters[key] = append(clusters[key], a.Value)
	}

	var result []HostCluster
	for k, members := range clusters {
		parts := strings.SplitN(k, ":", 2)
		clusterType := parts[0]
		name := parts[1]
		result = append(result, HostCluster{
			ID:          k,
			Name:        name,
			ClusterType: clusterType,
			Members:     members,
		})
	}
	return result
}
