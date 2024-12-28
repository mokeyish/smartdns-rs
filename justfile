
cargo := if env_var_or_default('USE_CROSS', 'false') == "true" { "cross" } else { "cargo" }

[private]
alias b := build

[private]
alias t := test

# Increment manifest version: major, minor, patch, rc, beta, alpha
bump +args: require_set-version
  @cargo set-version --bump {{args}}


# Print current version
version:
  @cargo pkgid | cut -d@ -f2


# Build
build *args: patch
  {{cargo}} build {{args}}


# Install
install *args: patch
  {{cargo}} install {{args}}


# Run tests
test *args: patch
  {{cargo}} test {{args}}


# Analyze the package and report errors, but don't build object files
check *args: patch
  {{cargo}} check --workspace --tests --benches --examples {{args}}

# Publish
publish *args: patch
  {{cargo}} publish --no-verify


# Run clippy fix
clippy: patch
  {{cargo}} clippy --fix --all


# format the code
fmt: patch
  {{cargo}} fmt --all


# Check the clippy and format.
cleanliness: patch
  cargo clippy
  cargo fmt --all -- --check


# cleanup the workspace
clean:
   cargo clean


# Apply patch
patch: # require_patch-crate
  @#cargo patch-crate -f


setcap:
  sudo find ./target -type f -name smartdns -exec setcap CAP_SYS_ADMIN,CAP_NET_ADMIN,CAP_NET_RAW,CAP_NET_BIND_SERVICE+eip  {} \;
  @find ./target -type f -name smartdns

[private]
@require_patch-crate:
  cargo patch-crate --version >/dev/null 2>&1 || cargo install patch-crate

[private]
@require_set-version:
  cargo set-version --version >/dev/null 2>&1 || cargo install cargo-edit > /dev/null
