SHELL := /bin/bash
ROOT  := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ENV   := source $(ROOT)/scripts/dev-env.sh &&

IMAGE  ?= out/beast-booter.img
SIZE   ?= 2G
LAYOUT ?= msdos
FS     ?= exfat

.PHONY: help tools keys build test image e2e clean dev doctor dev-image vm vm-sb menu-sync \
	sbom vulns portable lint release

help:
	@echo "make tools   fetch the build/test toolchain into .tools/ (no root needed)"
	@echo "make keys    create a local Secure Boot signing key in keys/"
	@echo "make build   build boot files into dist/"
	@echo "make test    run installer unit tests"
	@echo "make image   build a drive image: $(IMAGE) ($(SIZE), $(LAYOUT), $(FS))"
	@echo "make e2e     boot test images in QEMU (BIOS, UEFI, UEFI + Secure Boot)"
	@echo ""
	@echo "make dev        set up a complete dev environment (bin/bb-dev setup)"
	@echo "make doctor     check the dev environment and explain fixes"
	@echo "make dev-image  build out/dev/beast-booter-dev.img with test ISOs and debug on"
	@echo "make vm         boot the dev image in QEMU (MODE=bios|uefi|sb|sb-enrolled|sb-fresh)"
	@echo "make vm-sb      boot the dev image with Secure Boot (key enrolled)"
	@echo "make menu-sync  push edited grub/ files into the dev image (WATCH=1 to keep syncing)"
	@echo ""
	@echo "make lint       ruff (Python) + ShellCheck (shell) - see docs/CODE_QUALITY.md"
	@echo "make sbom       generate the SBOM into sbom/"
	@echo "make vulns      SBOM + vulnerability and boot-chain scan -> sbom/VULNERABILITIES.md"
	@echo "make portable   build the no-install portable package(s) into out/portable (ARGS=--all)"
	@echo "make release    build every release file locally into out/release (see docs/RELEASING.md)"

tools:
	./scripts/bootstrap-tools.sh

keys:
	$(ENV) ./build/keygen.sh

build:
	$(ENV) ./build/build.sh

test:
	$(ENV) pytest -q installer/tests

image:
	@mkdir -p $(dir $(IMAGE))
	$(ENV) python3 -m beastbooter install --image $(IMAGE) --size $(SIZE) \
		--layout $(LAYOUT) --fs $(FS) --yes

e2e:
	$(ENV) pytest -q tests/e2e

MODE ?= uefi

dev:
	bin/bb-dev setup --yes

doctor:
	bin/bb-dev doctor

dev-image:
	bin/bb-dev image --fixtures --debug

vm:
	bin/bb-dev vm --mode $(MODE)

vm-sb:
	bin/bb-dev vm --mode sb-enrolled

menu-sync:
	bin/bb-dev menu-sync $(if $(WATCH),--watch,)


sbom:
	$(ENV) bash ./scripts/sbom-vuln.sh sbom

vulns: sbom
	$(ENV) bash ./scripts/sbom-vuln.sh scan

portable:
	scripts/build_portable.sh $(ARGS)

lint:
	scripts/lint.sh $(ARGS)

release:
	scripts/release/build_release.sh $(ARGS)

clean:
	rm -rf dist out
