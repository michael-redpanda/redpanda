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

#pragma once

#include "bytes/bytes.h"
#include "container/fragmented_vector.h"
#include "debug_bundle/types.h"
#include "json/json.h"
#include "json/types.h"
#include "json/writer.h"
#include "utils/base64.h"

#include <chrono>
#include <filesystem>

namespace debug_bundle {
struct metadata {
    clock::time_point process_start_time_ms;
    chunked_vector<ss::sstring> cout;
    chunked_vector<ss::sstring> cerr;
    job_id_t job_id;
    std::filesystem::path debug_bundle_path;
    bytes sha256_checksum;

    friend bool operator==(const metadata&, const metadata&) = default;
};

template<typename Buffer, typename T, size_t fragment_size_bytes>
void rjson_serialize(
  ::json::Writer<Buffer>& w,
  const fragmented_vector<T, fragment_size_bytes>& v) {
    w.StartArray();
    for (const auto& e : v) {
        rjson_serialize(w, e);
    }
    w.EndArray();
}

template<typename Buffer>
void rjson_serialize(::json::Writer<Buffer>& w, const metadata& m) {
    w.StartObject();
    w.Key("process_start_time_ms");
    ::json::rjson_serialize(
      w,
      std::chrono::duration_cast<std::chrono::milliseconds>(
        m.process_start_time_ms.time_since_epoch())
        .count());
    w.Key("cout");
    rjson_serialize(w, m.cout);
    w.Key("cerr");
    rjson_serialize(w, m.cerr);
    w.Key("job_id");
    ::json::rjson_serialize(w, ss::sstring{m.job_id()});
    w.Key("debug_bundle_path");
    ::json::rjson_serialize(w, m.debug_bundle_path);
    w.Key("sha256_checksum");
    ::json::rjson_serialize(w, bytes_to_base64(m.sha256_checksum));
    w.EndObject();
}

ss::sstring serialize_metadata(metadata&& v);
metadata parse_metadata_json(const char* const s);
metadata parse_metadata_json(iobuf buf);
} // namespace debug_bundle
