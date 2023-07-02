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

#include "utils/external_process.h"
#include "utils/fragmented_vector.h"
#include "utils/gate_guard.h"
#include "utils/mutex.h"
#include "vlog.h"

#include <seastar/core/future.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/lowres_clock.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/smp.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/timer.hh>

#include <fmt/chrono.h>
#include <fmt/core.h>

#include <cstdlib>
#include <exception>
#include <system_error>

namespace {
ss::logger logger{"debug_bundle"};
constexpr auto syslog_time_format_string = "\"{:%Y-%m-%d %H:%M:%S}\"";
} // namespace

namespace debug_bundle {

void debug_bundle::debug_bundle_parameters::operator()(
  std::vector<ss::sstring>& param_vector) const noexcept {
    if (logs_since) {
        param_vector.emplace_back("--logs-since");
        param_vector.emplace_back(fmt::format(
          syslog_time_format_string, fmt::localtime(logs_since.value())));
    }

    if (logs_until) {
        param_vector.emplace_back("--logs-until");
        param_vector.emplace_back(fmt::format(
          syslog_time_format_string, fmt::localtime(logs_until.value())));
    }

    if (logs_size_limit) {
        param_vector.emplace_back("--logs-size-limit");
        param_vector.emplace_back(fmt::format("{}", logs_size_limit.value()));
    }

    if (metrics_interval) {
        param_vector.emplace_back("--metrics-interval");
        param_vector.emplace_back(
          fmt::format("{}s", metrics_interval.value().count()));
    }

    if (credentials) {
        credentials.value()(param_vector);
    }
}

std::ostream& operator<<(
  std::ostream& os, const debug_bundle::debug_bundle_parameters& parameters) {
    if (parameters.logs_since) {
        os << " --logs-since "
           << fmt::format(
                syslog_time_format_string,
                fmt::localtime(parameters.logs_since.value()));
    }

    if (parameters.logs_until) {
        os << " --logs-until "
           << fmt::format(
                syslog_time_format_string,
                fmt::localtime(parameters.logs_until.value()));
    }

    if (parameters.logs_size_limit) {
        os << " --logs-size-limit " << parameters.logs_size_limit.value();
    }

    if (parameters.metrics_interval) {
        os << " --metrics-interval "
           << parameters.metrics_interval.value().count() << "s";
    }

    if (parameters.credentials) {
        os << parameters.credentials.value();
    }
    return os;
}

std::ostream& operator<<(
  std::ostream& os, const debug_bundle::debug_bundle_credentials& credentials) {
    os << " --username " << credentials.username
       << " --password ******** --mechanism " << credentials.mechanism
       << (credentials.use_tls ? " --tls-enabled" : "");

    return os;
}

void debug_bundle::debug_bundle_credentials::operator()(
  std::vector<ss::sstring>& param_vector) const noexcept {
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
        if (_isstdout) {
            vlog(logger.trace, "stdout: {}", line);
        } else {
            vlog(logger.warn, "stderr: {}", line);
        }
        if (_string_buffer) {
            _string_buffer->get().emplace_back(std::move(line));
        }
    }
    return ss::make_ready_future<
      debug_bundle::debug_bundle_stream_handler::consumption_result_type>(
      ss::continue_consuming{});
}

ss::future<ss::sstring> debug_bundle::create_debug_bundle(
  debug_bundle::debug_bundle::debug_bundle_parameters bundle_parameters) {
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
          bundle_parameters, [this](auto& bundle_parameters) {
              return container().invoke_on(
                debug_bundle_shard_id, [bundle_parameters](debug_bundle& b) {
                    return b.create_debug_bundle(bundle_parameters);
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

    auto params = generate_rpk_parameters(temporary_path, bundle_parameters);

    std::vector<ss::sstring> env{_home_dir, _path_val};

    _rpk_process.emplace(
      ::external_process<debug_bundle::debug_bundle_stream_handler>::
        create_external_process(params, env));
    vlog(logger.debug, "Starting rpk process");
    try {
        co_await _rpk_process->run();
        vlog(logger.debug, "rpk process exited successfully");
    } catch (...) {
        vlog(logger.warn, "rpk process exiting with error");
        _rpk_process.reset();
        std::rethrow_exception(std::current_exception());
    }
    _rpk_process.reset();

    // now that the debug bundle has been successfully created
    // we need to move it to its new home
    vlog(
      logger.debug,
      "Moving bundle from {} to {}",
      temporary_path.string(),
      final_path.string());
    co_await ss::rename_file(temporary_path.c_str(), final_path.c_str());

    // seastar's doc state that the move is not guaranteed to be stable until
    // after the directories are synced
    try {
        co_await ss::sync_directory("/tmp");
    } catch (std::exception& e) {
        vlog(logger.error, "Failed to sync '/tmp': {}", e.what());
    }
    try {
        co_await ss::sync_directory(_output_directory.c_str());
    } catch (std::exception& e) {
        vlog(
          logger.error,
          "Failed to sync {}: {}",
          _output_directory.string(),
          e.what());
    }

    _stored_bundles[final_path.string()] = ss::lowres_clock::now();

    co_return final_path.string();
}

ss::future<errc> debug_bundle::stop_debug_bundle() {
    using namespace std::chrono_literals;
    static thread_local mutex stop_bundle_mutex;
    gate_guard g{_gate};

    auto try_result = stop_bundle_mutex.try_get_units();
    if (!try_result) {
        co_return errc::debug_bundle_stop_in_process;
    }

    if (ss::this_shard_id() != debug_bundle_shard_id) {
        co_return co_await container().invoke_on(
          debug_bundle_shard_id,
          [](debug_bundle& b) { return b.stop_debug_bundle(); });
    }

    if (_rpk_process) {
        vlog(logger.info, "Attempting to halt rpk bundle process");
        auto halt_result = co_await _rpk_process->terminate(5s);
        if (halt_result) {
            co_return errc::debug_bundle_process_not_running;
        }
    } else {
        co_return errc::debug_bundle_process_running;
    }

    vlog(logger.info, "Successfully halted rpk debug bundle process");
    co_return errc::success;
}

ss::sstring debug_bundle::generate_file_name() noexcept {
    auto now = std::chrono::system_clock::now();
    return fmt::format("{:%Y%m%d-%H%M%S}", now);
}

std::vector<ss::sstring> debug_bundle::generate_rpk_parameters(
  const std::filesystem::path& output_path,
  const debug_bundle_parameters& bundle_parameters) const noexcept {
    vlog(
      logger.trace,
      "{} debug bundle --output {}{}",
      _rpk_binary_path.string(),
      output_path.string(),
      bundle_parameters);
    std::vector<ss::sstring> args;
    args.emplace_back(_rpk_binary_path.string());
    args.emplace_back("debug");
    args.emplace_back("bundle");
    args.emplace_back("--output");
    args.emplace_back(output_path.string());
    bundle_parameters(args);

    return args;
}

ss::sstring debug_bundle::get_env_variable(const char* env) {
    auto env_var = std::getenv(env);
    if (!env_var) {
        vlog(
          logger.error,
          "Failed to find environmental variable {}.  The debug bundle may not "
          "contain all relevant debug information",
          env);
        return "";
    }
    return fmt::format("{}={}", env, env_var);
}

void debug_bundle::arm_debug_bundle_cleanup_timer() {
    ss::lowres_clock::time_point arm_until
      = _debug_bundle_cleanup_last_ran + get_debug_bundle_cleanup_period();

    _debug_bundle_cleanup_timer.arm(arm_until);
}

ss::lowres_clock::duration
debug_bundle::get_debug_bundle_cleanup_period() const noexcept {
    return _debug_bundle_cleanup_period;
}

ss::lowres_clock::duration debug_bundle::get_debug_bundle_ttl() const noexcept {
    return _debug_bundle_ttl;
}

ss::future<fragmented_vector<ss::sstring>> debug_bundle::bundles() {
    gate_guard g{_gate};

    if (ss::this_shard_id() != debug_bundle_shard_id) {
        co_return co_await container().invoke_on(
          debug_bundle_shard_id, [](debug_bundle& b) { return b.bundles(); });
    }

    fragmented_vector<ss::sstring> rv;
    for (auto& it : _stored_bundles) {
        rv.emplace_back(it.first);
    }

    co_return rv;
}

ss::future<std::error_code>
debug_bundle::delete_bundle(ss::sstring bundle_name) {
    gate_guard g{_gate};

    co_return co_await delete_bundle_no_gate(bundle_name);
}

ss::future<std::error_code>
debug_bundle::delete_bundle_no_gate(ss::sstring bundle_name) {
    auto iter = _stored_bundles.find(bundle_name);

    if (iter != _stored_bundles.end()) {
        auto err = errc::success;
        try {
            vlog(logger.debug, "Deleting {}", bundle_name);
            co_await ss::remove_file(bundle_name);
        } catch (std::exception& e) {
            vlog(
              logger.error, "Failed to delete {}: {}", bundle_name, e.what());
            err = errc::system_error;
        }

        _stored_bundles.erase(iter);

        co_return make_error_code(err);
    } else {
        co_return make_error_code(errc::debug_bundle_file_does_not_exist);
    }
}

ss::future<> debug_bundle::debug_bundle_cleanup() {
    _debug_bundle_cleanup_last_ran = ss::lowres_clock::now();

    auto last_allowed_time = ss::lowres_clock::now() + get_debug_bundle_ttl();

    for (auto it = _stored_bundles.begin(); it != _stored_bundles.end();) {
        if (it->second + get_debug_bundle_ttl() > last_allowed_time) {
            vlog(logger.debug, "Debug bundle at {} has expired", it->first);
            auto err = co_await delete_bundle_no_gate(it->first);
            if (err != errc::success) {
                vlog(logger.warn, "Failed to erase {}: {}", it->first, err);
            }

            _stored_bundles.erase(it++);
        } else {
            ++it;
        }
    }
}

ss::future<> debug_bundle::start() {
    vlog(logger.debug, "starting debug bundle service");
    _home_dir = debug_bundle::get_env_variable("HOME");
    _path_val = debug_bundle::get_env_variable("PATH");

    if (ss::this_shard_id() == debug_bundle_shard_id) {
        _debug_bundle_cleanup_timer.arm(
          ss::lowres_clock::now() + get_debug_bundle_cleanup_period());
    }

    return ss::make_ready_future<>();
}

ss::future<> debug_bundle::stop() {
    vlog(logger.debug, "stopping debug bundle service");

    if (ss::this_shard_id() == debug_bundle_shard_id) {
        _debug_bundle_cleanup_timer.cancel();
    }

    co_await _gate.close();

    // now we need to remove all those darn files
    co_await ss::parallel_for_each(_stored_bundles, [this](const auto& item) {
        return delete_bundle_no_gate(item.first).discard_result();
    });

    co_await ss::sync_directory(_output_directory.string()).discard_result();
}
} // namespace debug_bundle
