load("//bazel:test.bzl", "redpanda_cc_gtest")

redpanda_cc_gtest(
    name = "write_at_offset_stm_test",
    timeout = "moderate",
    srcs = [
        "write_at_offset_stm_test.cc",
    ],
    cpu = 1,
    deps = [
        "//src/v/cluster_link:write_at_offset_stm",
        "//src/v/config",
        "//src/v/model/tests:random",
        "//src/v/raft",
        "//src/v/raft/tests:stm_test_fixture",
        "//src/v/redpanda/tests:fixture",
        "//src/v/test_utils:gtest",
        "//src/v/test_utils:scoped_config",
        "@googletest//:gtest",
    ],
)
