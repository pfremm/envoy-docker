# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/envoy-control-plane ./cmd/envoy-control-plane

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/envoy-control-plane /envoy-control-plane
ENTRYPOINT ["/envoy-control-plane"]
