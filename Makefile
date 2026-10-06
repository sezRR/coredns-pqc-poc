.PHONY: up demo down test vet keys verify

up:
	docker compose up --build -d --wait coredns

demo: up
	docker compose run --rm verifier

down:
	docker compose down

test:
	go test -race ./...

vet:
	go vet ./...

keys:
	go run ./cmd/keygen -private-dir keys/native/private -public-dir keys/native/public

# Native mode has separate keys from the Compose volumes/public anchor copy.
verify:
	go run ./cmd/verify -trust-anchor keys/native/public/trust-anchor.ds -tamper
