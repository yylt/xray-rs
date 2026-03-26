PROTO_FILE := proto/grpc_transport.proto
GENERATED_DIR := src/generated
GENERATED_FILE := $(GENERATED_DIR)/grpc_generated.rs
CARGO_BIN_DIR := $(HOME)/.cargo/bin
PROTOC_GEN_PROST := $(CARGO_BIN_DIR)/protoc-gen-prost
PROTOC_GEN_TONIC := $(CARGO_BIN_DIR)/protoc-gen-tonic

.PHONY: tools generate build fmt test check clean-generated

tools:
	cargo install protoc-gen-prost --locked
	cargo install protoc-gen-tonic --locked

build:
	cargo build -r --bin xray-rs

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

check:
	cargo build

clean-generated:
	rm -f $(GENERATED_FILE)
