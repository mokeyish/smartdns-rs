

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

# cleanup the workspace
clean:
   cargo clean

apply-patch: init
  cargo patch-crate -f

# Initialize all tools needed
init:
  @cargo install patch-crate -q
  # @cargo patch-crate

