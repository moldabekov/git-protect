BINARY := git-protect
VERSION := 0.1.0
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint clean install

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/git-protect

test:
	go test -race -count=1 ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	go vet ./...

clean:
	rm -f $(BINARY) coverage.out

install: build
	go install $(LDFLAGS) ./cmd/git-protect
