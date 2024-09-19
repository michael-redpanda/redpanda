/*
 * Copyright 2024 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#include "debug_bundle/metadata.h"
#include "debug_bundle/types.h"
#include "json/json.h"
#include "utils/base64.h"
#include "utils/uuid.h"

#include <gtest/gtest.h>

#include <chrono>

namespace db = debug_bundle;

constexpr std::string_view job_id_test = "8fd28129-079e-4e7c-b7a9-e62e201dde36";
constexpr std::string_view debug_bundle_path_test
  = "/var/lib/redpanda/debug-bundle/8fd28129-079e-4e7c-b7a9-e62e201dde36.zip";
constexpr std::string_view base64_test
  = "EM6HmhI8rY0Ifwa8i8WzwjlhnZP7eNCkwM8wLXQcEfE=";
constexpr int64_t time_since_epoch_ms = 1726763763695;

// constexpr std::string_view metadata_sv{R"()"};
const auto metadata_str = fmt::format(
  R"(
{{
  "process_start_time_ms": {process_start_time_ms},
  "cout": ["cout", "output", "test"],
  "cerr": ["cerr", "output", "test"],
  "job_id": "{job_id}",
  "debug_bundle_path": "{debug_bundle_path}",
  "sha256_checksum": "{sha256_checksum}"
}})",
  fmt::arg("process_start_time_ms", time_since_epoch_ms),
  fmt::arg("job_id", job_id_test),
  fmt::arg("debug_bundle_path", debug_bundle_path_test),
  fmt::arg("sha256_checksum", base64_test));

const db::metadata metadata{
  .process_start_time_ms{std::chrono::milliseconds(time_since_epoch_ms)},
  .cout = {"cout", "output", "test"},
  .cerr = {"cerr", "output", "test"},
  .job_id = db::job_id_t{uuid_t::from_string(job_id_test)},
  .debug_bundle_path{debug_bundle_path_test},
  .sha256_checksum{base64_to_bytes(base64_test)}};

TEST(metadata_test, to_from) {
    auto test_metadata = db::parse_metadata_json(metadata_str.c_str());
    EXPECT_EQ(metadata, test_metadata);
    auto test_metadata_str = db::serialize_metadata(std::move(test_metadata));
    EXPECT_EQ(::json::minify(test_metadata_str), ::json::minify(metadata_str));
}
