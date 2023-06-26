// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#pragma once

#include "gate_guard.h"
#include "outcome.h"
#include "seastarx.h"
#include "vassert.h"

#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/when_all.hh>
#include <seastar/core/with_timeout.hh>
#include <seastar/util/log.hh>
#include <seastar/util/process.hh>

enum class external_process_errc : int {
    success = 0,
    exited_non_zero,
    exited_on_signal,
    process_does_not_exist,
};

struct external_process_errc_category final : public std::error_category {
    const char* name() const noexcept final { return "external_process_errc"; }

    std::string message(int c) const final {
        switch (static_cast<external_process_errc>(c)) {
        case external_process_errc::success:
            return "success";
        case external_process_errc::exited_non_zero:
            return "exited_non_zero";
        case external_process_errc::exited_on_signal:
            return "exited_on_signal";
        case external_process_errc::process_does_not_exist:
            return "process_does_not_exist";
        default:
            return "unknown";
        }
    }
};

inline const std::error_category& error_category() noexcept {
    static external_process_errc_category e;

    return e;
}
inline std::error_code make_error_code(external_process_errc e) noexcept {
    return std::error_code(static_cast<int>(e), error_category());
}

namespace std {
template<>
struct is_error_code_enum<external_process_errc> : true_type {};
} // namespace std

// This is here as a default for external_process
struct base_consumer {
    using consumption_result_type =
      typename ss::input_stream<char>::consumption_result_type;
    using stop_consuming_type =
      typename consumption_result_type::stop_consuming_type;
    using tmp_buf = stop_consuming_type::tmp_buf;
    ss::future<consumption_result_type> operator()(tmp_buf) {
        return ss::make_ready_future<consumption_result_type>(
          ss::continue_consuming{});
    }
};

template<
  typename StdoutConsumer = base_consumer,
  typename StderrConsumer = StdoutConsumer>
requires ss::InputStreamConsumer<StdoutConsumer, char>
         && ss::InputStreamConsumer<StderrConsumer, char>
class external_process {
public:
    static external_process create_external_process(
      std::vector<ss::sstring> command,
      std::optional<std::vector<ss::sstring>> env = std::nullopt) {
        ss::experimental::spawn_parameters params;
        auto path = std::filesystem::path(command[0]);
        params.argv = std::move(command);
        if (env) {
            params.env = env.value();
        }

        return external_process(path, params);
    }

    bool is_running() const noexcept { return _process.has_value(); }

    void set_stdout_consumer(StdoutConsumer&& consumer) noexcept {
        _stdout_consumer.emplace(std::move(consumer));
    }

    void set_stderr_consumer(StderrConsumer&& consumer) noexcept {
        _stderr_consumer.emplace(std::move(consumer));
    }

    ss::future<> run() {
        gate_guard g{_gate};
        vassert(!_process.has_value(), "Process already started");

        {
            auto p = co_await ss::experimental::spawn_process(_path, _params);
            _process.emplace(std::move(p));
        }

        std::vector<ss::future<>> futures;
        futures.reserve(3);

        futures.emplace_back(handle_process_wait());
        // We need to keep these items on the stack, if you do
        // _process->stdout().consume() the stream will deconstruct and
        // weird stuff happens
        auto stdout = _process->stdout();
        auto stderr = _process->stderr();

        if (_stdout_consumer) {
            futures.emplace_back(stdout.consume(*_stdout_consumer));
        }

        if (_stderr_consumer) {
            futures.emplace_back(stderr.consume(*_stderr_consumer));
        }

        auto res = co_await ss::when_all(futures.begin(), futures.end());
        _process = std::nullopt;
        for (auto& r : res) {
            r.get();
        }
    }

    template<
      typename Clock = ss::steady_clock_type,
      typename Rep,
      typename Period>
    ss::future<std::error_code>
    terminate(std::chrono::duration<Rep, Period> timeout) {
        gate_guard g{_gate};
        if (!_process) {
            return ss::make_ready_future<std::error_code>(
              make_error_code(external_process_errc::process_does_not_exist));
        }

        try {
            _process->terminate();
        } catch (...) {
            return ss::make_ready_future<std::error_code>(
              make_error_code(external_process_errc::process_does_not_exist));
        }

        bool cancel = false;

        return ss::do_with(
          cancel, timeout, [this](bool& cancel, auto& timeout) {
              return ss::with_timeout(
                       Clock::now() + timeout,
                       ss::do_until(
                         [this, &cancel] {
                             return !_process.has_value() || cancel;
                         },
                         [] {
                             return ss::sleep(std::chrono::milliseconds{10});
                         }))
                .then([] {
                    return ss::make_ready_future<std::error_code>(
                      make_error_code(external_process_errc::success));
                })
                .handle_exception_type(
                  [this, &cancel](const ss::timed_out_error&) {
                      cancel = true;
                      try {
                          _process->kill();
                          return ss::make_ready_future<std::error_code>(
                            make_error_code(external_process_errc::success));
                      } catch (...) {
                          return ss::make_ready_future<std::error_code>(
                            make_error_code(
                              external_process_errc::process_does_not_exist));
                      }
                  });
          });
    }

private:
    static ss::future<> test() { return ss::make_ready_future(); }
    explicit external_process(
      std::filesystem::path path, ss::experimental::spawn_parameters params)
      : _path(std::move(path))
      , _params(std::move(params)) {}

    ss::future<> handle_process_wait() {
        vassert(_process.has_value(), "_process not instantiated");
        auto result = co_await _process->wait();

        ss::visit(
          result,
          [this](ss::experimental::process::wait_exited exited) {
              if (exited.exit_code != 0) {
                  throw std::system_error(
                    make_error_code(external_process_errc::exited_non_zero),
                    fmt::format(
                      "Process {} exited with code {}",
                      _path.c_str(),
                      exited.exit_code));
              }
          },
          [this](ss::experimental::process::wait_signaled signaled) {
              throw std::system_error(
                make_error_code(external_process_errc::exited_on_signal),
                fmt::format(
                  "Process {} exited on signal {}",
                  _path.c_str(),
                  signaled.terminating_signal));
          });
    }

    std::filesystem::path _path;
    ss::experimental::spawn_parameters _params;
    std::optional<StdoutConsumer> _stdout_consumer;
    std::optional<StderrConsumer> _stderr_consumer;
    std::optional<ss::experimental::process> _process;
    ss::gate _gate;
};
