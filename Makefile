.PHONY: clean checks test build dependencies

SRCS = $(shell git ls-files '*.go' | grep -v '^vendor/')

ACMEPROXY_IMAGE := mdbraber/acmeproxy
MAIN_DIRECTORY := ./cmd/acmeproxy/
BIN_OUTPUT := dist/acmeproxy

TAG_NAME := $(shell git tag -l --contains HEAD)
SHA := $(shell git rev-parse HEAD)
VERSION := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))

default: clean checks test build

clean:
	rm -rf dist/ builds/ cover.out

debian-clean:
	dh_clean

build: clean
	@echo Version: $(VERSION)
	go build -v -ldflags '-X "main.version=${VERSION}"' -o ${BIN_OUTPUT} ${MAIN_DIRECTORY}

dependencies:
	dep ensure -v

test: clean
	go test -v -cover ./...

checks:
	golangci-lint run

fmt:
	gofmt -s -l -w $(SRCS)

install: build
	systemctl stop acmeproxy
	cp dist/acmeproxy /usr/local/bin
	systemctl start acmeproxy

debian: debian-clean build
	dpkg-buildpackage -us -uc -b --target-arch amd64
