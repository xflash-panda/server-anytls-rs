.PHONY: build release check test bench fmt lint clean run dev

# Development
dev: fmt lint test

# Build
build:
	cargo build

release:
	cargo build --release

check:
	cargo check

# Test
test:
	cargo test

bench:
	cargo bench

# Code quality
fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

lint:
	cargo clippy -- -D warnings

# Run
run:
	cargo run

# Clean
clean:
	cargo clean
