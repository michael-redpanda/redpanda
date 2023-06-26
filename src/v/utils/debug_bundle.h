// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#pragma once

#include "seastarx.h"
#include "utils/external_process.h"
#include "utils/gate_guard.h"

#include <seastar/core/sharded.hh>

namespace debug_bundle {

static constexpr ss::shard_id debug_bundle_shard_id = 0;

class debug_bundle final : public ss::peering_sharded_service<debug_bundle> {
public:
    struct debug_bundle_parameters {
        std::optional<struct tm> logs_since;
        std::optional<struct tm> logs_until;
        std::optional<ss::sstring> logs_size_limit;
    };
    debug_bundle(
      std::filesystem::path output_directory,
      std::filesystem::path rpk_binary_path)
      : _output_directory(std::move(output_directory))
      , _rpk_binary_path(std::move(rpk_binary_path)) {}

    ss::future<> start();

private:
    class debug_bundle_stream_handler final {
        using consumption_result_type =
          typename ss::input_stream<char>::consumption_result_type;
        using stop_consuming_type =
          typename consumption_result_type ::stop_consuming_type;
        using tmp_buf = stop_consuming_type::tmp_buf;

    public:
        debug_bundle_stream_handler(
          bool isstdout,
          std::optional<std::reference_wrapper<std::vector<ss::sstring>>>
            string_buffer
          = std::nullopt)
          : _isstdout(isstdout)
          , _string_buffer(std::move(string_buffer)) {}

        ss::future<consumption_result_type> operator()(tmp_buf buf);

    private:
        bool _isstdout;
        std::optional<std::reference_wrapper<std::vector<ss::sstring>>>
          _string_buffer;
    };

    std::filesystem::path _output_directory;
    std::filesystem::path _rpk_binary_path;
    std::optional<external_process<debug_bundle_stream_handler>> _rpk_process;
};

} // namespace debug_bundle