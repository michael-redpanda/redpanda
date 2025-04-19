load("//bazel:build.bzl", "redpanda_cc_library")
load("//src/v/rpc:compiler.bzl", "redpanda_cc_rpc_library")

redpanda_cc_rpc_library(
    name = "cluster_link_rpc",
    src = "rpc.json",
    include_prefix = "cluster_link/rpc",
)

redpanda_cc_library(
    name = "rpc",
    srcs = [
        "serde.cc",
        "service.cc",
    ],
    hdrs = [
        "serde.h",
        "service.h",
    ],
    include_prefix = "cluster_link/rpc",
    visibility = ["//visibility:public"],
    deps = [
        ":cluster_link_rpc",
        "//src/v/cluster",
        "//src/v/model",
        "//src/v/serde",
        "@fmt",
    ],
)
