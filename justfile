

build: init
  cargo build -r

# Run tests
test: init
  cargo test

# Run clippy
clippy: init
  cargo clippy --fix --all 

# Check the format
fmt: init
  cargo fmt --all

apply-patch:
  cargo patch-crate

# Initialize all tools needed
init:
  @cargo install patch-crate -q

