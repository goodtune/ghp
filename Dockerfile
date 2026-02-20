FROM python:3.13 AS docs
WORKDIR /src
COPY mkdocs.yml ./
COPY docs/ docs/
RUN pip install uv && uvx --with mkdocs-material mkdocs build --site-dir internal/docs/site

FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=docs /src/internal/docs/site internal/docs/site
RUN CGO_ENABLED=0 go build -ldflags '-X main.version=docker' -o /ghp ./cmd/ghp

FROM gcr.io/distroless/static-debian12
COPY --from=build /ghp /ghp
EXPOSE 8080
ENTRYPOINT ["/ghp"]
CMD ["serve"]
