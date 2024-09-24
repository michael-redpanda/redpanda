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

#include "debug_bundle_service.h"

#include "bytes/iostream.h"
#include "config/configuration.h"
#include "config/node_config.h"
#include "container/fragmented_vector.h"
#include "crypto/crypto.h"
#include "crypto/types.h"
#include "debug_bundle/error.h"
#include "debug_bundle/metadata.h"
#include "debug_bundle/types.h"
#include "ssx/future-util.h"
#include "utils/external_process.h"

#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/shard_id.hh>
#include <seastar/core/sstring.hh>
#include <seastar/util/defer.hh>
#include <seastar/util/process.hh>
#include <seastar/util/variant_utils.hh>

#include <boost/algorithm/string/join.hpp>
#include <fmt/format.h>

#include <optional>

using namespace std::chrono_literals;

namespace debug_bundle {
static ss::logger lg{"debug-bundle-service"};

namespace {
constexpr std::string_view output_variable = "--output";
constexpr std::string_view verbose_variable = "--verbose";
constexpr std::string_view username_variable = "-Xuser";
constexpr std::string_view password_variable = "-Xpass";
constexpr std::string_view sasl_mechanism_variable = "-Xsasl.mechanism";
constexpr std::string_view controller_logs_size_limit_variable
  = "--controller-logs-size-limit";
constexpr std::string_view cpu_profiler_wait_variable = "--cpu-profiler-wait";
constexpr std::string_view logs_since_variable = "--logs-since";
constexpr std::string_view logs_size_limit_variable = "--logs-size-limit";
constexpr std::string_view logs_until_variable = "--logs-until";
constexpr std::string_view metrics_interval_variable = "--metrics-interval";
constexpr std::string_view partition_variable = "--partition";

bool contains_sensitive_info(const ss::sstring& arg) {
    if (arg.find(password_variable) != ss::sstring::npos) {
        return true;
    }
    return false;
}
void print_arguments(const std::vector<ss::sstring>& args) {
    auto msg = boost::algorithm::join_if(args, " ", [](const ss::sstring& arg) {
        return !contains_sensitive_info(arg);
    });
    vlog(lg.debug, "Starting RPK debug bundle: {}", msg);
}

std::string form_debug_bundle_file_name(job_id_t job_id) {
    return fmt::format("{}.zip", job_id);
}

std::filesystem::path
form_metadata_file_path(const std::filesystem::path& base_path) {
    return base_path / service::metadata_file_name;
}

std::filesystem::path form_debug_bundle_file_path(
  const std::filesystem::path& base_path, job_id_t job_id) {
    return base_path / form_debug_bundle_file_name(job_id);
}

std::filesystem::path form_debug_bundle_storage_directory() {
    const auto& debug_bundle_dir
      = config::shard_local_cfg().debug_bundle_storage_dir();

    // Either return the storage directory or the data directory appended with
    // "debug-bundle"
    return debug_bundle_dir.value_or(
      config::node().data_directory.value().path
      / service::debug_bundle_dir_name);
}

ss::future<bytes> calculate_sha256_sum(const std::filesystem::path& file_path) {
    const size_t buffer_size = 8192;
    crypto::digest_ctx ctx(crypto::digest_type::SHA256);
    auto handle = co_await ss::open_file_dma(
      file_path.native(), ss::open_flags::ro);
    auto file_size = co_await handle.size();
    size_t total_consumed = 0;
    auto h = ss::defer(
      [handle]() mutable { ssx::background = handle.close(); });

    auto stream = ss::make_file_input_stream(
      handle,
      ss::file_input_stream_options{
        .buffer_size = buffer_size,
        .read_ahead = 1,
      });

    while (total_consumed < file_size) {
        auto data = co_await stream.read_up_to(
          std::min(buffer_size, file_size - total_consumed));
        total_consumed += data.size();
        ctx.update({data.get(), data.size()});
    }

    co_return std::move(ctx).final();
}

ss::future<metadata> get_metadata(const std::string_view debug_bundle_path) {
    iobuf buf;
    auto handle = co_await ss::open_file_dma(
      debug_bundle_path.data(), ss::open_flags::ro);
    auto h = ss::defer(
      [handle]() mutable { ssx::background = handle.close(); });
    auto istr = ss::make_file_input_stream(handle);
    auto ostrm = make_iobuf_ref_output_stream(buf);
    co_await ss::copy(istr, ostrm);
    co_return parse_metadata_json(std::move(buf));
}

ss::future<bool> validate_sha256_checksum(
  const std::filesystem::path& file_path, const bytes& checksum) {
    auto calculated_checksum = co_await calculate_sha256_sum(file_path);
    co_return calculated_checksum == checksum;
}
} // namespace

struct service::output_handler {
    using consumption_result_type =
      typename ss::input_stream<char>::consumption_result_type;
    using stop_consuming_type =
      typename consumption_result_type::stop_consuming_type;
    using tmp_buf = stop_consuming_type::tmp_buf;

    chunked_vector<ss::sstring>& output_buffer;

    ss::future<consumption_result_type> operator()(tmp_buf buf) {
        output_buffer.emplace_back(ss::sstring{buf.begin(), buf.end()});
        co_return ss::continue_consuming{};
    }
};

class service::debug_bundle_process {
public:
    debug_bundle_process(
      job_id_t job_id,
      std::unique_ptr<external_process::external_process> rpk_process,
      std::filesystem::path output_directory)
      : _job_id(job_id)
      , _rpk_process(std::move(rpk_process))
      , _output_directory(std::move(output_directory))
      , _created_time(clock::now()) {
        _rpk_process->set_stdout_consumer(
          output_handler{.output_buffer = _cout});
        _rpk_process->set_stderr_consumer(
          output_handler{.output_buffer = _cerr});
    }

    debug_bundle_process(
      job_id_t job_id,
      ss::experimental::process::wait_status wait_result,
      std::filesystem::path output_directory,
      chunked_vector<ss::sstring> cout,
      chunked_vector<ss::sstring> cerr,
      clock::time_point created_time)
      : _job_id(job_id)
      , _wait_result(wait_result)
      , _output_directory(std::move(output_directory))
      , _cout(std::move(cout))
      , _cerr(std::move(cerr))
      , _created_time(created_time) {}

    debug_bundle_process() = delete;
    debug_bundle_process(debug_bundle_process&&) = default;
    debug_bundle_process& operator=(debug_bundle_process&&) = default;
    debug_bundle_process(const debug_bundle_process&) = delete;
    debug_bundle_process& operator=(const debug_bundle_process&) = delete;

    ~debug_bundle_process() {
        if (_rpk_process) {
            vassert(
              !_rpk_process->is_running(),
              "Destroying process struct without waiting for process to "
              "finish");
        }
    }

    ss::future<> terminate(std::chrono::milliseconds timeout) {
        if (_rpk_process) {
            co_await _rpk_process->terminate(timeout);
        }
    }

    ss::future<ss::experimental::process::wait_status> wait() {
        vassert(
          _rpk_process, "RPK process should be created if calling wait()");
        co_return co_await _rpk_process->wait();
    }

    std::optional<debug_bundle_status> process_status() const {
        if (_wait_result.has_value()) {
            return ss::visit(
              _wait_result.value(),
              [](ss::experimental::process::wait_exited e) {
                  if (e.exit_code == 0) {
                      return debug_bundle_status::success;
                  } else {
                      return debug_bundle_status::error;
                  }
              },
              [](ss::experimental::process::wait_signaled) {
                  return debug_bundle_status::error;
              });
        }
        return debug_bundle_status::running;
    }

    bool is_running() const {
        if (auto status = process_status();
            status.has_value() && *status == debug_bundle_status::running) {
            return true;
        } else {
            return false;
        }
    }

    void emplace_wait_result(ss::experimental::process::wait_status result) {
        _wait_result.emplace(result);
    }

    job_id_t job_id() const { return _job_id; }
    const std::filesystem::path& output_directory() const {
        return _output_directory;
    }
    const chunked_vector<ss::sstring>& cout() const { return _cout; }
    const chunked_vector<ss::sstring>& cerr() const { return _cerr; }
    clock::time_point created_time() const { return _created_time; }

private:
    job_id_t _job_id;
    std::unique_ptr<external_process::external_process> _rpk_process;
    std::optional<ss::experimental::process::wait_status> _wait_result;
    std::filesystem::path _output_directory;
    chunked_vector<ss::sstring> _cout;
    chunked_vector<ss::sstring> _cerr;
    clock::time_point _created_time;
};

service::service()
  : _debug_bundle_dir(form_debug_bundle_storage_directory())
  , _debug_bundle_storage_dir_binding(
      config::shard_local_cfg().debug_bundle_storage_dir.bind())
  , _rpk_path_binding(config::shard_local_cfg().rpk_path.bind())
  , _process_control_mutex("debug_bundle_service::process_control") {
    _debug_bundle_storage_dir_binding.watch([this] {
        _debug_bundle_dir = form_debug_bundle_storage_directory();
        lg.debug("Changed debug bundle directory to {}", _debug_bundle_dir);
    });
}

service::~service() noexcept = default;

ss::future<> service::start() {
    if (ss::this_shard_id() != service_shard) {
        co_return;
    }

    if (!co_await ss::file_exists(_debug_bundle_dir.native())) {
        try {
            lg.trace("Creating {}", _debug_bundle_dir);
            co_await ss::recursive_touch_directory(_debug_bundle_dir.native());
        } catch (const std::exception& e) {
            throw std::system_error(error_code::internal_error, e.what());
        }
    }

    if (!co_await ss::file_exists(_rpk_path_binding().native())) {
        lg.error(
          "Current specified RPK location {} does not exist!  Debug "
          "bundle creation is not available until this is fixed!",
          _rpk_path_binding().native());
    }

    lg.debug("Service started");
}

ss::future<> service::stop() {
    lg.debug("Service stopping");
    if (ss::this_shard_id() == service_shard) {
        if (is_running()) {
            try {
                co_await _rpk_process->terminate(1s);
            } catch (const std::exception& e) {
                lg.warn(
                  "Failed to terminate running process while stopping service: "
                  "{}",
                  e.what());
            }
        }
    }
    co_await _gate.close();
}

ss::future<result<void>> service::initiate_rpk_debug_bundle_collection(
  job_id_t job_id, debug_bundle_parameters params) {
    auto hold = _gate.hold();
    if (ss::this_shard_id() != service_shard) {
        co_return co_await container().invoke_on(
          service_shard,
          [job_id, params = std::move(params)](service& s) mutable {
              return s.initiate_rpk_debug_bundle_collection(
                job_id, std::move(params));
          });
    }
    auto units = co_await _process_control_mutex.get_units();
    if (!co_await ss::file_exists(_rpk_path_binding().native())) {
        co_return error_info(
          error_code::rpk_binary_not_present,
          fmt::format("{} not present", _rpk_path_binding().native()));
    }

    if (_rpk_process) {
        // Must wait for both the process to no longer be running and for the
        // wait result to be populated
        if (is_running()) {
            co_return error_info(
              error_code::debug_bundle_process_running,
              "Debug process already running");
        }
    }

    try {
        co_await cleanup_previous_run();
    } catch (const std::exception& e) {
        co_return error_info(
          error_code::internal_error,
          fmt::format("Failed to clean up previous run: {}", e.what()));
    }

    // Make a copy of it now and use it throughout the initialize process
    // Protects against a situation where the config gets changed while setting
    // up the initialization parameters
    auto output_dir = _debug_bundle_dir;

    if (!co_await ss::file_exists(output_dir.native())) {
        try {
            co_await ss::recursive_touch_directory(output_dir.native());
        } catch (const std::exception& e) {
            co_return error_info(
              error_code::internal_error,
              fmt::format(
                "Failed to create debug bundle directory {}: {}",
                output_dir,
                e.what()));
        }
    }

    auto debug_bundle_file_path = form_debug_bundle_file_path(
      output_dir, job_id);

    auto args = build_rpk_arguments(debug_bundle_file_path, std::move(params));
    if (lg.is_enabled(ss::log_level::debug)) {
        print_arguments(args);
    }

    try {
        _rpk_process = std::make_unique<debug_bundle_process>(
          job_id,
          co_await external_process::external_process::create_external_process(
            std::move(args)),
          output_dir);
    } catch (const std::exception& e) {
        _rpk_process.reset();
        co_return error_info(
          error_code::internal_error,
          fmt::format("Starting rpk debug bundle failed: {}", e.what()));
    }

    // Kick off the wait by waiting for the process to finish and then emplacing
    // the result
    ssx::spawn_with_gate(_gate, [this, job_id]() {
        return _rpk_process->wait()
          .then([this, job_id](auto res) {
              // This ensures in the extremely unlikely case where this
              // continuation is called after another debug bundle has been
              // initiated that we are accessing a present and valid
              // _rpk_process
              if (!_rpk_process || _rpk_process->job_id() != job_id) {
                  return ss::now();
              }
              _rpk_process->emplace_wait_result(res);
              return construct_metadata(job_id);
          })
          .handle_exception_type([this](const std::exception& e) {
              lg.error(
                "wait() failed while running rpk debug bundle: {}", e.what());
              _rpk_process->emplace_wait_result(
                ss::experimental::process::wait_exited{1});
          });
    });

    co_return outcome::success();
}

ss::future<result<void>> service::cancel_rpk_debug_bundle(job_id_t job_id) {
    auto hold = _gate.hold();
    if (ss::this_shard_id() != service_shard) {
        co_return co_await container().invoke_on(
          service_shard,
          [job_id](service& s) { return s.cancel_rpk_debug_bundle(job_id); });
    }
    auto units = co_await _process_control_mutex.get_units();
    auto status = process_status();
    if (!status.has_value()) {
        co_return error_info(error_code::debug_bundle_process_never_started);
    } else if (!is_running()) {
        co_return error_info(error_code::debug_bundle_process_not_running);
    }

    vassert(
      _rpk_process,
      "_rpk_process should be populated if the process has been executed");

    if (job_id != _rpk_process->job_id()) {
        co_return error_info(error_code::job_id_not_recognized);
    }

    try {
        co_await _rpk_process->terminate(1s);
    } catch (const std::system_error& e) {
        if (
          e.code() == external_process::error_code::process_already_completed) {
            co_return error_info(error_code::debug_bundle_process_not_running);
        }
        co_return (error_info(error_code::internal_error, e.what()));
    } catch (const std::exception& e) {
        co_return error_info(error_code::internal_error, e.what());
    }

    co_return outcome::success();
}

ss::future<result<debug_bundle_status_data>>
service::rpk_debug_bundle_status() {
    auto hold = _gate.hold();
    if (ss::this_shard_id() != service_shard) {
        co_return co_await container().invoke_on(service_shard, [](service& s) {
            return s.rpk_debug_bundle_status();
        });
    }
    auto status = process_status();
    if (!status.has_value()) {
        co_return error_info(error_code::debug_bundle_process_never_started);
    }

    vassert(
      _rpk_process,
      "_rpk_process should be populated if the process has been executed");

    co_return debug_bundle_status_data{
      .job_id = _rpk_process->job_id(),
      .status = status.value(),
      .created_timestamp = _rpk_process->created_time(),
      .file_name = form_debug_bundle_file_name(_rpk_process->job_id()),
      .cout = _rpk_process->cout().copy(),
      .cerr = _rpk_process->cerr().copy()};
}

ss::future<result<std::filesystem::path>> service::rpk_debug_bundle_path() {
    if (ss::this_shard_id() != service_shard) {
        co_return co_await container().invoke_on(
          service_shard, [](service& s) { return s.rpk_debug_bundle_path(); });
    }
    co_return error_info(error_code::debug_bundle_process_never_started);
}

ss::future<result<void>> service::delete_rpk_debug_bundle() {
    if (ss::this_shard_id() != service_shard) {
        co_return co_await container().invoke_on(service_shard, [](service& s) {
            return s.delete_rpk_debug_bundle();
        });
    }
    co_return error_info(error_code::debug_bundle_process_never_started);
}

std::vector<ss::sstring> service::build_rpk_arguments(
  const std::filesystem::path& debug_bundle_file_path,
  debug_bundle_parameters params) {
    std::vector<ss::sstring> rv{
      _rpk_path_binding().native(), "debug", "bundle"};
    rv.emplace_back(output_variable);
    rv.emplace_back(debug_bundle_file_path);
    rv.emplace_back(verbose_variable);
    if (params.authn_options.has_value()) {
        ss::visit(
          params.authn_options.value(),
          [&rv](const scram_creds& creds) mutable {
              rv.emplace_back(
                ssx::sformat("{}={}", username_variable, creds.username));
              rv.emplace_back(
                ssx::sformat("{}={}", password_variable, creds.password));
              rv.emplace_back(ssx::sformat(
                "{}={}", sasl_mechanism_variable, creds.mechanism));
          });
    }
    if (params.controller_logs_size_limit_bytes.has_value()) {
        rv.emplace_back(controller_logs_size_limit_variable);
        rv.emplace_back(
          ssx::sformat("{}B", params.controller_logs_size_limit_bytes.value()));
    }
    if (params.cpu_profiler_wait_seconds.has_value()) {
        rv.emplace_back(cpu_profiler_wait_variable);
        rv.emplace_back(ssx::sformat(
          "{}s", params.cpu_profiler_wait_seconds.value().count()));
    }
    if (params.logs_since.has_value()) {
        rv.emplace_back(logs_since_variable);
        rv.emplace_back(ssx::sformat("{}", params.logs_since.value()));
    }
    if (params.logs_size_limit_bytes.has_value()) {
        rv.emplace_back(logs_size_limit_variable);
        rv.emplace_back(
          ssx::sformat("{}B", params.logs_size_limit_bytes.value()));
    }
    if (params.logs_until.has_value()) {
        rv.emplace_back(logs_until_variable);
        rv.emplace_back(ssx::sformat("{}", params.logs_until.value()));
    }
    if (params.metrics_interval_seconds.has_value()) {
        rv.emplace_back(metrics_interval_variable);
        rv.emplace_back(
          ssx::sformat("{}s", params.metrics_interval_seconds.value().count()));
    }
    if (params.partition.has_value()) {
        rv.emplace_back(partition_variable);
        rv.emplace_back(
          ssx::sformat("{}", fmt::join(params.partition.value(), " ")));
    }

    return rv;
}

ss::future<> service::cleanup_previous_run() const {
    if (_rpk_process == nullptr) {
        co_return;
    }

    auto debug_bundle_file = form_debug_bundle_file_path(
      _rpk_process->output_directory(), _rpk_process->job_id());
    if (co_await ss::file_exists(debug_bundle_file.native())) {
        co_await ss::remove_file(debug_bundle_file.native());
    }

    auto metadata_file = form_metadata_file_path(
      _rpk_process->output_directory());
    if (co_await ss::file_exists(metadata_file.native())) {
        co_await ss::remove_file(metadata_file.native());
    }

    co_await ss::sync_directory(_rpk_process->output_directory().native());
}

ss::future<> service::construct_metadata(job_id_t job_id) {
    auto units = co_await _process_control_mutex.get_units();
    // Again, double check that _rpk_process is present and matches the job ID
    if (!_rpk_process || _rpk_process->job_id() != job_id) {
        vlog(
          lg.debug,
          "Unable to construct metadata for {}, another process already "
          "started",
          job_id());
        co_return;
    }

    auto file_path = form_debug_bundle_file_path(
      _rpk_process->output_directory(), job_id);
    if (!co_await ss::file_exists(file_path.native())) {
        vlog(
          lg.warn, "Debug bundle file has been removed earlier than expected");
        co_return;
    }

    auto metadata_str = serialize_metadata(
      {.process_start_time_ms = _rpk_process->created_time(),
       .cout = _rpk_process->cout().copy(),
       .cerr = _rpk_process->cerr().copy(),
       .job_id = job_id,
       .debug_bundle_path = file_path,
       .sha256_checksum = co_await calculate_sha256_sum(file_path)});

    auto metadata_file_path = form_metadata_file_path(
      _rpk_process->output_directory());

    if (co_await ss::file_exists(metadata_file_path.native())) {
        co_await ss::remove_file(metadata_file_path.native());
        co_await ss::sync_directory(_rpk_process->output_directory().native());
    }

    auto handle = co_await ss::open_file_dma(
      metadata_file_path.native(), ss::open_flags::create | ss::open_flags::wo);
    auto h = ss::defer(
      [handle]() mutable { ssx::background = handle.close(); });
    auto ostr = co_await ss::make_file_output_stream(handle);
    co_await ostr.write(metadata_str.data(), metadata_str.size());
    co_await ostr.flush();
    co_await ss::sync_directory(_rpk_process->output_directory().native());
}

std::optional<debug_bundle_status> service::process_status() const {
    if (_rpk_process) {
        return _rpk_process->process_status();
    }
    return std::nullopt;
}

bool service::is_running() const {
    if (_rpk_process) {
        return _rpk_process->is_running();
    }
    return false;
}

ss::future<> service::maybe_reload_previous_run() {
    const auto metadata_file = form_metadata_file_path(_debug_bundle_dir);
    if (!co_await ss::file_exists(metadata_file.native())) {
        co_return;
    }
    vlog(lg.debug, "Detected metadata file at {}", metadata_file);
    metadata md;
    try {
        md = co_await get_metadata(metadata_file.native());
    } catch (const std::exception& e) {
        vlog(
          lg.info,
          "Failed to read metadata from {}: {}",
          metadata_file,
          e.what());
        co_return;
    }
    if (!co_await ss::file_exists(md.debug_bundle_path.native())) {
        vlog(
          lg.info,
          "Detected metadata file at {} but debug bundle file {} is missing.  "
          "Removing metadata file",
          metadata_file,
          md.debug_bundle_path);
        co_await ss::remove_file(metadata_file.native());
        co_return;
    }
    if (!co_await validate_sha256_checksum(
          md.debug_bundle_path.native(), md.sha256_checksum)) {
        vlog(lg.info, "Checksum mismatch for {}", md.debug_bundle_path);
        co_await ss::remove_file(metadata_file.native());
        co_await ss::remove_file(md.debug_bundle_path.native());
        co_return;
    }
    vlog(
      lg.info,
      "Detected metadata file at {} and debug bundle file {} is present and "
      "valid.  Reloading metadata",
      metadata_file,
      md.debug_bundle_path);
}

} // namespace debug_bundle
