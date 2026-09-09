TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=registry.terraform.io
NAMESPACE=CheckPointSW
NAME=checkpointsase
BINARY=terraform-provider-${NAME}
VERSION=3.0.0
OS_ARCH=$(shell go env GOOS)_$(shell go env GOARCH)

# Mirrors .goreleaser.yml, so a local build reports the same version a released
# one does. main.go has to DECLARE version and commit for these to land: the Go
# linker ignores -X against a symbol that does not exist, silently, which is why
# the release flags did nothing before those declarations were added.
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS=-X main.version=${VERSION} -X main.commit=${COMMIT}

default: install

build:
	go build -ldflags "${LDFLAGS}" -o ${BINARY}

release:
	GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_darwin_amd64
	GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_darwin_arm64
	GOOS=freebsd GOARCH=386 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_freebsd_386
	GOOS=freebsd GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_freebsd_amd64
	GOOS=freebsd GOARCH=arm go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_freebsd_arm
	GOOS=linux GOARCH=386 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_linux_386
	GOOS=linux GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_linux_amd64
	GOOS=linux GOARCH=arm go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_linux_arm
	GOOS=linux GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_linux_arm64
	GOOS=openbsd GOARCH=386 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_openbsd_386
	GOOS=openbsd GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_openbsd_amd64
	GOOS=solaris GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_solaris_amd64
	GOOS=windows GOARCH=386 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_windows_386
	GOOS=windows GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o ./bin/${BINARY}_${VERSION}_windows_amd64

PLUGIN_DIR=~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

install: build
	mkdir -p ${PLUGIN_DIR}
	mv ${BINARY} ${PLUGIN_DIR}

test: 
	go test -i $(TEST) || exit 1                                                   
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=12                  

testacc:
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

# Tier 1: no API calls. Must pass with CHECKPOINT_SASE_API_KEY unset.
testunit:
	go test ./checkpointsase/

.PHONY: default build release install test testacc testunit
