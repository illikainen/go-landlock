OUTPUT ?= $(shell pwd)/build/
GOFER ?= gofer
SANDBOX ?= $(GOFER) run --

MODULE := $(shell grep '^module' go.mod|cut -d' ' -f2)

export CGO_ENABLED := 0
export GO111MODULE := on
export GOFLAGS := -mod=readonly
export GOSUMDB := sum.golang.org
export REAL_GOPROXY := $(shell go env GOPROXY)
export GOPROXY := off

# Unfortunately there is no Go-specific way of pinning the CA for GOPROXY.
# The go.pem file is created by the `pin` target in this Makefile.
export SSL_CERT_FILE := ./go.pem
export SSL_CERT_DIR := /path/does/not/exist/to/pin/ca

define PIN_EXPLANATION
# The checksums for go.sum and go.mod are pinned because `go mod` with
# `-mod=readonly` isn't read-only.  The `go mod` commands will still modify the
# dependency tree if they find it necessary (e.g., to add a missing module or
# module checksum).
#
# Run `make pin` to update this file.
endef
export PIN_EXPLANATION

all:

tidy:
	@GOPROXY=$(REAL_GOPROXY) go mod tidy
	@$(SANDBOX) go mod verify

prepare-offline: tidy
	@GOPROXY=$(REAL_GOPROXY) go list -m -json all >/dev/null

clean:
	@$(SANDBOX) go clean
	@$(SANDBOX) go clean -cache
	@$(SANDBOX) rm -rfv $(OUTPUT)

distclean:
	@$(SANDBOX) git clean -d -f -x

test:
	@$(SANDBOX) mkdir -p $(OUTPUT)
	@$(SANDBOX) go test -v -coverprofile=$(OUTPUT)/.coverage -coverpkg=./... ./...

coverage:
	@$(SANDBOX) go tool cover -func $(OUTPUT)/.coverage

check-nilerr:
	@$(SANDBOX) echo "Running nilerr"
	@$(SANDBOX) nilerr ./...

check-errcheck:
	@$(SANDBOX) echo "Running errcheck"
	@$(SANDBOX) errcheck ./...

check-revive:
	@$(SANDBOX) echo "Running revive"
	@$(SANDBOX) revive -config revive.toml -set_exit_status ./...

check-gosec:
	@$(SANDBOX) echo "Running gosec"
	@$(SANDBOX) gosec -quiet ./...

check-staticcheck:
	@$(SANDBOX) echo "Running staticcheck"
	@$(SANDBOX) staticcheck ./...

check-vet:
	@$(SANDBOX) echo "Running go vet"
	@$(SANDBOX) go vet ./...

check-fmt:
	@$(SANDBOX) echo "Running gofmt"
	@$(SANDBOX) gofmt -d -l .

check-imports:
	@$(SANDBOX) echo "Running goimports"
	@$(SANDBOX) goimports -d -local $(MODULE) -l .

check-yamllint:
	@$(SANDBOX) echo "Running yamllint"
	@$(SANDBOX) yamllint --strict .

#check: verify check-nilerr check-errcheck check-revive check-gosec \
#	check-staticcheck check-vet check-fmt check-imports check-yamllint
check: verify check-errcheck check-revive check-vet check-fmt check-imports check-yamllint

fix-fmt:
	@$(SANDBOX) gofmt -w -l .

fix-imports:
	@$(SANDBOX) goimports -w -l -local $(MODULE) .

fix: verify fix-fmt fix-imports

pin:
	@$(SANDBOX) echo "$$PIN_EXPLANATION" > go.pin 2>&1
	@$(SANDBOX) sha256sum go.sum go.mod >> go.pin 2>&1
	@test -f /etc/ssl/certs/GTS_Root_R1.pem && test -f /etc/ssl/certs/GTS_Root_R4.pem && \
		cat /etc/ssl/certs/GTS_Root_R1.pem /etc/ssl/certs/GTS_Root_R4.pem > go.pem || true

verify:
	@$(SANDBOX) sha256sum --strict --check go.pin
	@$(SANDBOX) go mod verify

qa: check test

.PHONY: all tidy clean distclean
.PHONY: test coverage prepare-offline
.PHONY: check check-nilerr check-errcheck check-revive check-gosec
.PHONY: check-staticcheck check-vet check-fmt check-imports check-yamllint
.PHONY: fix-imports fix-fmt fix pin verify qa
