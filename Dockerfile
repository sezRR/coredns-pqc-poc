FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/coredns ./cmd/coredns
RUN CGO_ENABLED=0 go build -trimpath -o /out/keygen ./cmd/keygen
RUN CGO_ENABLED=0 go build -trimpath -o /out/verify ./cmd/verify

FROM scratch
COPY --from=build /out/ /usr/local/bin/
COPY Corefile /Corefile
EXPOSE 1053/udp 1053/tcp
ENTRYPOINT ["/usr/local/bin/coredns"]
CMD ["-conf", "/Corefile"]
