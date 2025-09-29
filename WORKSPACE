load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_features",
    sha256 = "9390b391a68d3b24aef7966bce8556d28003fe3f022a5008efc7807e8acaaf1a",
    strip_prefix = "bazel_features-1.36.0",
    url = "https://github.com/bazel-contrib/bazel_features/releases/download/v1.36.0/bazel_features-v1.36.0.tar.gz",
)

load("@bazel_features//:deps.bzl", "bazel_features_deps")

bazel_features_deps()

http_archive(
    name = "rules_rust",
    integrity = "sha256-YrnH/f8jCpEqGAU+keNqauc+QSde9egtcFXqPtJuee4=",
    urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.65.0/rules_rust-0.65.0.tar.gz"],
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains()

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies()

load("@rules_rust//crate_universe:defs.bzl", "crates_repository")

crates_repository(
    name = "symbolic_crate_index",
    cargo_lockfile = "//:Cargo.lock",
    manifests = [
        "//:Cargo.toml",
        "//:symbolic/Cargo.toml",
        "//:symbolic-cabi/Cargo.toml",
        "//:symbolic-cfi/Cargo.toml",
        "//:symbolic-common/Cargo.toml",
        "//:symbolic-debuginfo/Cargo.toml",
        "//:symbolic-demangle/Cargo.toml",
        "//:symbolic-il2cpp/Cargo.toml",
        "//:symbolic-ppdb/Cargo.toml",
        "//:symbolic-sourcemapcache/Cargo.toml",
        "//:symbolic-symcache/Cargo.toml",
        "//:symbolic-unreal/Cargo.toml",
    ],
)

load("@symbolic_crate_index//:defs.bzl", "crate_repositories")

crate_repositories()
