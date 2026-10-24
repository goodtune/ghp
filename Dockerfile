FROM python:3.14 AS docs
WORKDIR /src
COPY mkdocs.yml ./
COPY docs/ docs/
RUN pip install uv && uvx --with mkdocs-shadcn==0.10.2 mkdocs build --site-dir internal/docs/site

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=docs /src/internal/docs/site internal/docs/site
RUN CGO_ENABLED=0 go build -ldflags '-X main.version=docker' -o /ghp ./cmd/ghp

FROM gcr.io/distroless/static-debian12
COPY --from=build /ghp /ghp
USER nonroot:nonroot
EXPOSE 8080
# webhooks.nats.listen (e.g. 4222) is optional and off by default; publish it
# explicitly when native NATS subscribers are enabled. The JetStream store
# (webhooks.nats.store_dir) must point at a writable volume, e.g.
# GHP_WEBHOOKS_NATS_STORE_DIR=/data/nats with a volume mounted at /data.
ENTRYPOINT ["/ghp"]
CMD ["serve", "--migrate"]
