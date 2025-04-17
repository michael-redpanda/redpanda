load("//bazel:build.bzl", "redpanda_cc_library")

redpanda_cc_library(
    name = "logger",
    srcs = [
        "logger.cc",
    ],
    hdrs = [
        "logger.h",
    ],
    include_prefix = "cluster_link",
    visibility = [":__subpackages__"],
    deps = [
        "//src/v/base",
        "@seastar",
    ],
)

redpanda_cc_library(
    name = "write_at_offset_stm",
    srcs = [
        "write_at_offset_stm.cc",
    ],
    hdrs = [
        "write_at_offset_stm.h",
    ],
    implementation_deps = [
        ":logger",
    ],
    include_prefix = "cluster_link",
    visibility = ["//visibility:public"],
    deps = [
        "//src/v/cluster:snapshot",
        "//src/v/cluster:state_machine_registry",
        "//src/v/model:batch_utils",
        "//src/v/raft",
        "//src/v/raft:fundamental",
        "@seastar",
    ],
)
