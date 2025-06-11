load("//bazel:test.bzl", "redpanda_cc_gtest")

redpanda_cc_gtest(
    name = "link_test",
    timeout = "short",
    srcs = [
        "link_test.cc",
    ],
    deps = [
        "//src/v/cluster",
        "//src/v/cluster/cluster_link/tests:test_lib",
        "//src/v/cluster_link:impl",
        "//src/v/model",
        "//src/v/test_utils:gtest",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@googletest//:gtest",
        "@seastar",
    ],
)

redpanda_cc_gtest(
    name = "errc_test",
    timeout = "short",
    srcs = [
        "errc_test.cc",
    ],
    deps = [
        "//src/v/cluster_link:errc",
        "//src/v/test_utils:gtest",
        "@googletest//:gtest",
    ],
)

redpanda_cc_gtest(
    name = "base_task_test",
    timeout = "short",
    srcs = [
        "base_task_test.cc",
    ],
    deps = [
        "//src/v/cluster_link:impl",
        "//src/v/test_utils:gtest",
        "@googletest//:gtest",
        "@seastar",
    ],
)
