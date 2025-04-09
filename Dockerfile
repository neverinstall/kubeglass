ARG GO_VERSION=1.21
FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --no-cache build-base clang llvm elfutils-libelf-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN cd cmd/kubeglass && go generate

RUN cd cmd/kubeglass && CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /kubeglass .

FROM alpine:latest

RUN apk add --no-cache elfutils-libelf

COPY --from=builder /kubeglass /usr/local/bin/kubeglass

ENTRYPOINT ["/usr/local/bin/kubeglass"]
