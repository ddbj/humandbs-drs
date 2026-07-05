# Build all binaries once, then expose one per target stage.
FROM golang:1.26 AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ENV CGO_ENABLED=0
RUN go build \
      -ldflags "-X github.com/ddbj/humandbs-drs/internal/buildinfo.Version=${VERSION} -X github.com/ddbj/humandbs-drs/internal/buildinfo.Commit=${COMMIT} -X github.com/ddbj/humandbs-drs/internal/buildinfo.Date=${DATE}" \
      -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian12 AS drs
COPY --from=build /out/drs /drs
EXPOSE 28000
ENTRYPOINT ["/drs"]

FROM gcr.io/distroless/static-debian12 AS issuer
COPY --from=build /out/issuer /issuer
EXPOSE 28001
ENTRYPOINT ["/issuer"]

FROM gcr.io/distroless/static-debian12 AS s3-ingest
COPY --from=build /out/drs-s3-ingest /drs-s3-ingest
ENTRYPOINT ["/drs-s3-ingest"]
