/*
 * Copyright 2023 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#include "debug_bundle.h"

#include "vlog.h"

static ss::logger logger{"debug_bundle"};

namespace debug_bundle {
ss::future<debug_bundle::debug_bundle_stream_handler::consumption_result_type>
debug_bundle::debug_bundle_stream_handler::operator()(
  debug_bundle::debug_bundle::debug_bundle_stream_handler::tmp_buf buf) {
    const std::string strbuf{buf.begin(), buf.end()};
    std::string line;
    std::stringstream ss(strbuf);
    while (!ss.eof()) {
        std::getline(ss, line);
        vlog(logger.trace, "{}: {}", _isstdout ? "stdout" : "stderr", line);
        if (_string_buffer) {
            _string_buffer->get().emplace_back(std::move(line));
        }
    }
    return ss::make_ready_future<
      debug_bundle::debug_bundle_stream_handler::consumption_result_type>(
      ss::continue_consuming{});
}
} // namespace debug_bundle