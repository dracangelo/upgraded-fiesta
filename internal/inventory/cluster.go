package inventory

import (
	"net"
	"strings"

	"enumscan/internal/models"
)

type HostCluster struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	ClusterType string   `json:"cluster_type"`
	Members     []string `json:"members"`
}

type HostClusterer struct{}

func NewHostClusterer() *HostClusterer {
	return &HostClusterer{}
}

func (hc *HostClusterer) ClusterAssets(assets []models.InventoryAsset) []HostCluster {
	clusters := make(map[string][]string)

	for _, a := range assets {
		key := "asset:other"
		if ip := net.ParseIP(a.Value); ip != nil && ip.To4() != nil {
			parts := strings.Split(a.Value, ".")
			key = "subnet:" + parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
		} else if ip := net.ParseIP(a.Value); ip != nil && ip.To4() == nil {
			key = "subnet:ipv6_group"
		} else if domain := registrableDomain(a.Value); domain != "" {
			key = "domain:" + domain
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

func registrableDomain(value string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(value, ".")), ".")
	if len(labels) < 2 {
		return ""
	}
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}
