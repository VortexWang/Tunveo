FROM golang:1.26.5-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/tunveo ./cmd/tunveo

FROM scratch
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /out/tunveo /tunveo
COPY LICENSE NOTICE /usr/share/licenses/tunveo/
COPY internal/tunnelpool/tcp/LICENSE /usr/share/licenses/tunveo/tcp/LICENSE
COPY internal/tunnelpool/quic/LICENSE /usr/share/licenses/tunveo/quic/LICENSE
COPY internal/tunnelpool/websocket/LICENSE /usr/share/licenses/tunveo/websocket/LICENSE
COPY internal/tunnelpool/http2/LICENSE /usr/share/licenses/tunveo/http2/LICENSE
ENTRYPOINT ["/tunveo"]
