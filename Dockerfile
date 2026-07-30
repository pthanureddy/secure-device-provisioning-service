FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/controlplane ./cmd/controlplane

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/controlplane /controlplane
EXPOSE 8080 8883
ENTRYPOINT ["/controlplane"]

