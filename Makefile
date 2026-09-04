.PHONY: build test check lint lint-linux shellcheck test-scripts frontend frontend-test cross-arm64 bundle-openwrt-arm64 openwrt-apk-arm64 deploy-openwrt

VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
DIST_DIR ?= dist
OPENWRT_BUNDLE ?= $(DIST_DIR)/boxctl-openwrt-linux-arm64.tar.gz
MODULE_PATH := $(shell go list -m)
LDFLAGS := -s -w \
	-X $(MODULE_PATH)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE_PATH)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE_PATH)/internal/buildinfo.Date=$(DATE)
POSIX_SHELL_SCRIPTS := \
	packaging/openwrt/install.sh \
	packaging/openwrt/files/etc/init.d/boxctl \
	packaging/openwrt/files/etc/hotplug.d/iface/40-boxctl \
	packaging/openwrt/files/etc/hotplug.d/net/99-boxctl-tun \
	scripts/calver.sh \
	scripts/deploy-openwrt.sh \
	scripts/release-notes.sh \
	scripts/test-calver.sh \
	scripts/test-deploy-openwrt.sh \
	scripts/test-release-notes.sh \
	scripts/validate-calver.sh \
	tests/integration/guest/run.sh \
	tests/integration/guest/traffic.sh
BASH_SHELL_SCRIPTS := \
	scripts/build-openwrt-apk.sh \
	tests/integration/fetch-openwrt.sh \
	tests/integration/run.sh
SHELL_SCRIPTS := $(POSIX_SHELL_SCRIPTS) $(BASH_SHELL_SCRIPTS)
OPENWRT_INTEGRATION_FILES := \
	packaging/openwrt/files/etc/apk/protected_paths.d/boxctl.list \
	packaging/openwrt/files/etc/config/boxctl \
	packaging/openwrt/files/etc/hotplug.d/iface/40-boxctl \
	packaging/openwrt/files/etc/hotplug.d/net/99-boxctl-tun \
	packaging/openwrt/files/etc/init.d/boxctl \
	packaging/openwrt/files/lib/upgrade/keep.d/boxctl

build: frontend
	mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/boxctl ./cmd/boxctl

test: frontend frontend-test test-scripts
	go test ./...

check: test lint lint-linux shellcheck
	go vet ./...
	git diff --check

lint:
	golangci-lint run ./...

lint-linux:
	CGO_ENABLED=0 GOOS=linux golangci-lint run ./...

shellcheck:
	shellcheck $(SHELL_SCRIPTS)

test-scripts:
	sh -n $(POSIX_SHELL_SCRIPTS)
	bash -n $(BASH_SHELL_SCRIPTS)
	sh scripts/test-calver.sh
	sh scripts/test-deploy-openwrt.sh
	sh scripts/test-release-notes.sh

frontend:
	npm --prefix frontend run build

frontend-test:
	npm --prefix frontend test

cross-arm64: frontend
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/boxctl-linux-arm64 ./cmd/boxctl

bundle-openwrt-arm64: cross-arm64
	@set -eu; \
		mkdir -p "$(DIST_DIR)"; \
		bundle_tmp=$$(mktemp -d "$(abspath $(DIST_DIR))/.boxctl-openwrt.XXXXXX"); \
		trap 'rm -rf "$$bundle_tmp"' EXIT HUP INT TERM; \
		bundle_root="$$bundle_tmp/root"; \
		mkdir -p "$$bundle_root"; \
		install -m 0755 "$(DIST_DIR)/boxctl-linux-arm64" "$$bundle_root/boxctl-linux-arm64"; \
		install -m 0755 packaging/openwrt/install.sh "$$bundle_root/install.sh"; \
		install -m 0644 LICENSE "$$bundle_root/LICENSE"; \
		for source in $(OPENWRT_INTEGRATION_FILES); do \
			target="$$bundle_root/$${source#packaging/openwrt/}"; \
			install -d "$$(dirname "$$target")"; \
			cp -p "$$source" "$$target"; \
		done; \
		TZ=UTC find "$$bundle_root" -exec touch -t 197001010000 {} +; \
		(cd "$$bundle_root" && find . -print | LC_ALL=C sort > "$$bundle_tmp/manifest"); \
		COPYFILE_DISABLE=1 tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner \
			-C "$$bundle_root" -cf "$$bundle_tmp/bundle.tar" -T "$$bundle_tmp/manifest"; \
		gzip -n -9 "$$bundle_tmp/bundle.tar"; \
		mv -f "$$bundle_tmp/bundle.tar.gz" "$(OPENWRT_BUNDLE)"; \
		trap - EXIT HUP INT TERM; \
		rm -rf "$$bundle_tmp"; \
		printf 'created %s\n' "$(OPENWRT_BUNDLE)"

openwrt-apk-arm64: cross-arm64
	VERSION="$(VERSION)" BINARY="$(abspath $(DIST_DIR))/boxctl-linux-arm64" DIST_DIR="$(abspath $(DIST_DIR))" \
		./scripts/build-openwrt-apk.sh

deploy-openwrt:
	./scripts/deploy-openwrt.sh
