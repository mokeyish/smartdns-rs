

build: apply-patch
  cargo build -r

# Run tests
test: apply-patch
  cargo test

# Run clippy
clippy: apply-patch
  cargo clippy --fix --all 

# Check the format
fmt: apply-patch
  cargo fmt --all

apply-patch: init
  cargo patch-crate

# Initialize all tools needed
init:
  @cargo install patch-crate -q

