# Multi-stage build for the parcagpu admission webhook
# Standalone Go binary — no external dependencies at runtime.

FROM golang:1.25.1 AS builder

WORKDIR /build

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /parcagpu-webhook .

FROM gcr.io/distroless/static:nonroot AS runtime

COPY --from=builder /parcagpu-webhook /usr/local/bin/parcagpu-webhook

ENTRYPOINT ["/usr/local/bin/parcagpu-webhook"]
CMD ["-cert", "/certs/tls.crt", "-key", "/certs/tls.key", "-port", "8443"]
