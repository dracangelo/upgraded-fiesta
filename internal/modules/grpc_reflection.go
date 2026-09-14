package modules

import (
	"context"
	"net"
	"strconv"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	reflection "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

// GRPCReflectionEnumerator performs the read-only ListServices reflection
// request on explicitly configured ports. It never invokes an advertised RPC.
type GRPCReflectionEnumerator struct {
	db    store.RuntimeStore
	guard scope.Guard
	ports map[int]bool
}

func NewGRPCReflectionEnumerator(db store.RuntimeStore, guard scope.Guard, cfg models.HTTPConfig) *GRPCReflectionEnumerator {
	ports := make(map[int]bool, len(cfg.GRPCReflectionPorts))
	for _, port := range cfg.GRPCReflectionPorts {
		if port >= 1 && port <= 65535 {
			ports[port] = true
		}
	}
	return &GRPCReflectionEnumerator{db: db, guard: guard, ports: ports}
}
func (m *GRPCReflectionEnumerator) Name() string            { return "grpc_reflection_enumerator" }
func (m *GRPCReflectionEnumerator) Subscriptions() []string { return []string{EventPort} }
func (m *GRPCReflectionEnumerator) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	host, portText, err := net.SplitHostPort(event.Target)
	if err != nil || !m.guard.Allowed(host) {
		return nil, nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil || !m.ports[port] {
		return nil, nil
	}
	connection, err := grpc.DialContext(ctx, event.Target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, nil
	}
	defer connection.Close()
	stream, err := reflection.NewServerReflectionClient(connection).ServerReflectionInfo(ctx)
	if err != nil {
		return nil, nil
	}
	if err := stream.Send(&reflection.ServerReflectionRequest{Host: host, MessageRequest: &reflection.ServerReflectionRequest_ListServices{ListServices: ""}}); err != nil {
		return nil, nil
	}
	response, err := stream.Recv()
	if err != nil || response.GetListServicesResponse() == nil {
		return nil, nil
	}
	for _, service := range response.GetListServicesResponse().Service {
		if service.Name == "" {
			continue
		}
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "grpc_service", Value: service.Name, Parent: event.Target, Metadata: "source=grpc_reflection;verification=observed"})
	}
	return nil, nil
}
