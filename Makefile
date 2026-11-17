PROTO_FILE := proto/grpc_transport.proto
GENERATED_DIR := src/generated
GENERATED_FILE := $(GENERATED_DIR)/grpc_generated.rs
CARGO_BIN_DIR := $(HOME)/.cargo/bin
PROTOC_GEN_PROST := $(CARGO_BIN_DIR)/protoc-gen-prost
PROTOC_GEN_TONIC := $(CARGO_BIN_DIR)/protoc-gen-tonic

XRAY_CORE_BIN ?= $(abspath ../Xray-Core/xray)

.PHONY: tools generate build build-xray fmt test e2e e2e-compat check clippy ci clean-generated

tools:
	cargo install protoc-gen-prost --locked
	cargo install protoc-gen-tonic --locked

build:
	cargo build -r --bin xray-rs

build-xray:
	cargo build --bin xray-rs

generate:
	@mkdir -p $(GENERATED_DIR)
	@tmpdir=$$(mktemp -d); \
	protoc \
		--proto_path=proto \
		--prost_out=$$tmpdir \
		--tonic_out=$$tmpdir \
		--plugin=protoc-gen-prost=$(PROTOC_GEN_PROST) \
		--plugin=protoc-gen-tonic=$(PROTOC_GEN_TONIC) \
		$(PROTO_FILE); \
		sed '/^include!("rsray\.grpc\.tonic\.rs");$$/d' $$tmpdir/rsray/grpc/rsray.grpc.rs > $(GENERATED_FILE); \
		cat $$tmpdir/rsray/grpc/rsray.grpc.tonic.rs >> $(GENERATED_FILE); \
		rm -rf $$tmpdir

fmt:
	cargo fmt

test:
	cargo test

e2e: build-xray
	./tests/e2e/run_xray_tests.sh

e2e-compat: build-xray
	./tests/e2e/run_xray_tests.sh -core "$(XRAY_CORE_BIN)"

check:
	cargo build --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

ci: fmt clippy check test
	@echo "CI: all checks passed"

clean-generated:
	rm -f $(GENERATED_FILE)
