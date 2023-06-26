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
#include "utils/human.h"

#include <seastar/core/sharded.hh>

namespace debug_bundle {

enum class errc : int {
    success = 0,
    debug_bundle_process_running,
};

struct errc_category final : public std::error_category {
    const char* name() const noexcept final { return "debug_bundle::errc"; }

    std::string message(int c) const final {
        switch (static_cast<errc>(c)) {
        case errc::success:
            return "success";
        case errc::debug_bundle_process_running:
            return "debug_bundle_process_running";
        default:
            return "debug_bundle::errc::unknown";
        }
    }
};

inline const std::error_category& error_category() noexcept {
    static errc_category e;
    return e;
}

inline std::error_code make_error_code(errc e) noexcept {
    return std::error_code(static_cast<int>(e), error_category());
}

static constexpr ss::shard_id debug_bundle_shard_id = 0;

class debug_bundle final : public ss::peering_sharded_service<debug_bundle> {
public:
    struct debug_bundle_parameters {
        std::optional<std::chrono::time_point<std::chrono::system_clock>>
          logs_since;
        std::optional<std::chrono::time_point<std::chrono::system_clock>>
          logs_until;
        std::optional<human::golang_bytes> logs_size_limit;
        std::optional<std::chrono::seconds> metrics_interval;

        void operator()(std::vector<ss::sstring> & param_vector) const noexcept;
    };
    struct debug_bundle_credentials {
        ss::sstring username;
        ss::sstring password;
        ss::sstring mechanism;
        bool use_tls;

        void operator()(std::vector<ss::sstring> & param_vector) const noexcept;
    };
    debug_bundle(
      std::filesystem::path output_directory,
      std::filesystem::path rpk_binary_path)
      : _output_directory(std::move(output_directory))
      , _rpk_binary_path(std::move(rpk_binary_path)) {}

    ss::future<bool> is_running() noexcept {
        co_return co_await container().invoke_on(
          debug_bundle_shard_id,
          [](debug_bundle& b) { return b._rpk_process.has_value(); });
    }

    ss::future<> create_debug_bundle(
      debug_bundle_parameters bundle_parameters,
      std::optional<debug_bundle_credentials> credentials);

    ss::future<> start();

private:
    class debug_bundle_stream_handler final {
        using consumption_result_type =
          typename ss::input_stream<char>::consumption_result_type;
        using stop_consuming_type =
          typename consumption_result_type ::stop_consuming_type;
        using tmp_buf = stop_consuming_type::tmp_buf;

    public:
        explicit debug_bundle_stream_handler(
          bool isstdout,
          std::optional<std::reference_wrapper<std::vector<ss::sstring>>>
            string_buffer
          = std::nullopt)
          : _isstdout(isstdout)
          , _string_buffer(string_buffer) {}

        ss::future<consumption_result_type> operator()(tmp_buf buf);

    private:
        bool _isstdout;
        std::optional<std::reference_wrapper<std::vector<ss::sstring>>>
          _string_buffer;
    };

    static ss::sstring generate_file_name() noexcept;
    std::vector<ss::sstring> generate_rpk_parameters(
      const std::filesystem::path & output_path,
      const debug_bundle_parameters& bundle_parameters,
      const std::optional<debug_bundle_credentials>& credentials)
      const noexcept;

    std::filesystem::path _output_directory;
    std::filesystem::path _rpk_binary_path;
    ss::sstring _home_dir;
    ss::sstring _path_val;
    std::optional<external_process<debug_bundle_stream_handler>> _rpk_process;
    ss::gate _gate;
};

} // namespace debug_bundle

namespace std {
template<>
struct is_error_code_enum<debug_bundle::errc> : true_type {};
} // namespace std