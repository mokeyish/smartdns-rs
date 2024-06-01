
cargo := if env_var_or_default('USE_CROSS', 'false') == "true" { "cross" } else { "cargo" }

# Increment manifest version: major, minor, patch, rc, beta, alpha
bump +args:
  @cargo set-version --bump {{args}}


# Print current version
version:
  @cargo pkgid | cut -d@ -f2


# Build
build *args: init
  {{cargo}} build {{args}}


# Run tests
test *args: init
  {{cargo}} test {{args}}


# Analyze the package and report errors, but don't build object files
check *args: init
  {{cargo}} check --workspace --tests --benches --examples {{args}}


# Run clippy fix
clippy: init
  {{cargo}} clippy --fix --all


# format the code
fmt: init
  {{cargo}} fmt --all


# Check the clippy and format.
cleanliness: init
  cargo clippy
  cargo fmt --all -- --check


# cleanup the workspace
clean:
   cargo clean


apply-patch: init
  cargo patch-crate -f


# Initialize all tools needed
init:
  @cargo patch-crate --version || cargo install patch-crate
  @cargo set-version --version || cargo install cargo-edit
  @#@cargo patch-crate
