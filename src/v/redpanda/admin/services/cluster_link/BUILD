load("//bazel:build.bzl", "redpanda_cc_library")

redpanda_cc_library(
    name = "cluster_link",
    srcs = ["cluster_link.cc"],
    hdrs = ["cluster_link.h"],
    include_prefix = "redpanda/admin/services/cluster_link",
    visibility = ["//src/v/redpanda:__subpackages__"],
    deps = [
        "//proto/redpanda/core/admin:cluster_link_redpanda_proto",
        "//src/v/serde/protobuf:rpc",
    ],
)
