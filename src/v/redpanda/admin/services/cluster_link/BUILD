load("//bazel:build.bzl", "redpanda_cc_library")

redpanda_cc_library(
    name = "converter",
    srcs = ["converter.cc"],
    hdrs = ["converter.h"],
    include_prefix = "redpanda/admin/services/cluster_link",
    visibility = ["//src/v/redpanda/admin/services/cluster_link:__subpackages__"],
    deps = [
        "//proto/redpanda/core/admin:cluster_link_redpanda_proto",
        "//src/v/cluster_link/model",
    ],
)

redpanda_cc_library(
    name = "cluster_link",
    srcs = ["cluster_link.cc"],
    hdrs = ["cluster_link.h"],
    implementation_deps = [
        ":converter",
        "//src/v/cluster_link",
    ],
    include_prefix = "redpanda/admin/services/cluster_link",
    visibility = ["//src/v/redpanda:__subpackages__"],
    deps = [
        "//proto/redpanda/core/admin:cluster_link_redpanda_proto",
        "//src/v/cluster_link:fwd",
        "//src/v/serde/protobuf:rpc",
        "@seastar",
    ],
)
