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

#include "utils/mutex.h"
#include "vlog.h"

#include <fmt/chrono.h>

static ss::logger logger{"debug_bundle"};

namespace debug_bundle {

void debug_bundle::debug_bundle_parameters::operator()(std::vector<ss::sstring> & param_vector) const noexcept {

    if (logs_since) {
        param_vector.emplace_back("--logs-since");
        param_vector.emplace_back(fmt::format(
          "{:%Y-%m-%d %H:%M:%S}", fmt::localtime(logs_since.value())));
    }

    if (logs_until) {
        param_vector.emplace_back("--logs-until");
        param_vector.emplace_back(fmt::format(
          "{:%Y-%m-%d %H:%M:%S}", fmt::localtime(logs_until.value())));
    }

    if (logs_size_limit) {
        param_vector.emplace_back("--logs-size-limit");
        param_vector.emplace_back(fmt::format("{}", logs_size_limit.value()));
    }

    if (metrics_interval) {
        param_vector.emplace_back("--metrics-interval");
        param_vector.emplace_back(fmt::format("{}s", metrics_interval.value().count()));
    }
}

void debug_bundle::debug_bundle_credentials::operator()(std::vector<ss::sstring>& param_vector) const noexcept {
    param_vector.emplace_back("--username");
    param_vector.emplace_back(username);
    param_vector.emplace_back("--password");
    param_vector.emplace_back(password);
    param_vector.emplace_back("--mechanism");
    param_vector.emplace_back(mechanism);
    if (use_tls) {
        param_vector.emplace_back("--tls-enabled");
    }
}

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

ss::future<> debug_bundle::create_debug_bundle(
  debug_bundle::debug_bundle::debug_bundle_parameters bundle_parameters,
  std::optional<debug_bundle_credentials> credentials) {
    // thread local mutex to prevent another shard from trying to fire off a new
    // bundle process while one is in action
    static thread_local mutex create_bundle_mutex;
    gate_guard g{_gate};
    auto try_result = create_bundle_mutex.try_get_units();
    if (!try_result) {
        throw std::system_error(
          make_error_code(errc::debug_bundle_process_running));
    }

    if (ss::this_shard_id() != debug_bundle_shard_id) {
        co_return co_await ss::do_with(
          bundle_parameters,
          credentials,
          [this](auto& bundle_parameters, auto& credentials) {
              return container().invoke_on(
                debug_bundle_shard_id,
                [bundle_parameters, credentials](debug_bundle& b) {
                    return b.create_debug_bundle(
                      bundle_parameters, credentials);
                });
          });
    }

    if (co_await is_running()) {
        throw std::system_error(
          make_error_code(errc::debug_bundle_process_running));
    }

    auto file_name = generate_file_name();
    auto temporary_path = std::filesystem::path("/tmp")
                          / std::filesystem::path(file_name);
    auto final_path = _output_directory / std::filesystem::path(file_name);

    auto params = generate_rpk_parameters(temporary_path, bundle_parameters, credentials);

    std::vector<ss::sstring> env;


    _rpk_process.emplace(::external_process<debug_bundle::debug_bundle_stream_handler>::create_external_process(params));
}

ss::sstring debug_bundle::generate_file_name() noexcept {
    auto now = std::chrono::system_clock::now();
    return fmt::format("{:%Y%m%d-%H%M%S}", now);
}

std::vector<ss::sstring> debug_bundle::generate_rpk_parameters(
  const std::filesystem::path & output_path,
  const debug_bundle_parameters& bundle_parameters,
  const std::optional<debug_bundle_credentials>& credentials) const noexcept {
    std::vector<ss::sstring> args;
    args.emplace_back(_rpk_binary_path.string());
    args.emplace_back("debug");
    args.emplace_back("bundle");
    args.emplace_back("--output");
    args.emplace_back(output_path.string());
    bundle_parameters(args);

    if (credentials) {
        credentials.value()(args);
    }

    return args;
}
} // namespace debug_bundle