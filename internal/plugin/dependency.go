package plugin

import (
	"fmt"
)

type DependencyNode struct {
	Name         string
	Dependencies []string
}

type DependencyResolver struct{}

func NewDependencyResolver() *DependencyResolver {
	return &DependencyResolver{}
}

func (r *DependencyResolver) ResolveExecutionOrder(nodes []DependencyNode) ([]string, error) {
	inDegree := make(map[string]int)
	graph := make(map[string][]string)

	for _, n := range nodes {
		if _, exists := inDegree[n.Name]; !exists {
			inDegree[n.Name] = 0
		}
		for _, dep := range n.Dependencies {
			graph[dep] = append(graph[dep], n.Name)
			inDegree[n.Name]++
		}
	}

	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	var order []string
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		order = append(order, curr)

		for _, neighbor := range graph[curr] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	if len(order) != len(inDegree) {
		return nil, fmt.Errorf("circular plugin dependency detected")
	}

	return order, nil
}
