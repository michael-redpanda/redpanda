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
