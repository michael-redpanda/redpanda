load("//bazel:build.bzl", "redpanda_cc_library")

package(default_visibility = ["//src/v/redpanda/admin:__subpackages__"])

redpanda_cc_library(
    name = "admin",
    srcs = ["admin.cc"],
    hdrs = ["admin.h"],
    include_prefix = "redpanda/admin/services",
    deps = [
        "//proto/redpanda/core/admin:admin_redpanda_proto",
        "//src/v/version",
        "@seastar",
    ],
)

redpanda_cc_library(
    name = "cluster_link",
    srcs = ["cluster_link.cc"],
    hdrs = ["cluster_link.h"],
    include_prefix = "redpanda/admin/services",
    visibility = ["//src/v/redpanda:__subpackages__"],
    deps = [
        "//proto/redpanda/core/admin:cluster_link_redpanda_proto",
        "//src/v/serde/protobuf:rpc",
    ],
)
