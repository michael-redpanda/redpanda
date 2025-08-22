load("//bazel:test.bzl", "redpanda_cc_gtest")

redpanda_cc_gtest(
    name = "converter_test",
    srcs = [
        "converter_test.cc",
    ],
    timeout = "short",
    deps = [
        "//src/v/test_utils:gtest",
        "//src/v/redpanda/admin/services/shadow_link:converter",
        "@googletest//:gtest"
    ]
)