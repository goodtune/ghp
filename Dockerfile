FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags '-X main.version=docker' -o /ghp ./cmd/ghp

FROM gcr.io/distroless/static-debian12
COPY --from=build /ghp /ghp
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/ghp"]
CMD ["serve", "--migrate"]
