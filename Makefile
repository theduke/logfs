
lint-fmt:
	cargo fmt --all --check

lint-clippy:
	cargo clippy --all-targets --all-features -- -D warnings

lint: lint-fmt lint-clippy


test:
	cargo test --all-features
