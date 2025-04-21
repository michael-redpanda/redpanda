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
    visibility = ["//src/v/cluster_link:__subpackages__"],
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

redpanda_cc_library(
    name = "fwd",
    hdrs = [
        "fwd.h",
    ],
    include_prefix = "cluster_link",
    visibility = ["//visibility:public"],
)

redpanda_cc_library(
    name = "cluster_link",
    srcs = [
        "api.cc",
    ],
    hdrs = [
        "api.h",
    ],
    implementation_deps = [
        ":impl",
        ":logger",
        "//src/v/kafka/client",
        "//src/v/kafka/server",
        "//src/v/utils:unresolved_address",
    ],
    include_prefix = "cluster_link",
    visibility = ["//visibility:public"],
    deps = [
        ":fwd",
        "//src/v/base",
        "//src/v/cluster",
        "//src/v/model",
        "//src/v/raft",
        "//src/v/transform/rpc",
        "@seastar",
    ],
)

redpanda_cc_library(
    name = "impl",
    srcs = [
        "panda_link.cc",
        "panda_link_manager.cc",
    ],
    hdrs = [
        "panda_link.h",
        "panda_link_manager.h",
    ],
    implementation_deps = [
        ":logger",
        "//src/v/kafka/protocol:metadata",
        "//src/v/ssx:future_util",
        "@fmt",
    ],
    include_prefix = "cluster_link",
    visibility = ["//src/v/cluster_link:__subpackages__"],
    deps = [
        ":fwd",
        "//src/v/base",
        "//src/v/kafka/client",
        "//src/v/model",
        "//src/v/ssx:work_queue",
        "//src/v/transform/rpc",
        "//src/v/utils:unresolved_address",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@seastar",
    ],
)
