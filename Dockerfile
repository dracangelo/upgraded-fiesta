# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=true -ldflags='-s -w' -o /out/enumscan ./cmd/enumscan

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/enumscan /usr/local/bin/enumscan
USER nonroot:nonroot
VOLUME ["/data"]
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/enumscan"]
CMD ["-config", "/data/enumscan.yaml", "server"]
