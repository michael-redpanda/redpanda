// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include <system_error>

#include <utils/external_process.h>

#include <seastar/core/do_with.hh>
#include <seastar/core/future.hh>
#include <seastar/core/sleep.hh>
#include <seastar/testing/thread_test_case.hh>


using consumption_result_type = typename ss::input_stream<char>::consumption_result_type;
using stop_consuming_type = typename consumption_result_type::stop_consuming_type;
using tmp_buf = stop_consuming_type::tmp_buf;

SEASTAR_THREAD_TEST_CASE(external_process_start) {
    ss::do_with(bool(false), [](auto & matched) {
               struct consumer {
                   consumer(std::string_view expected, bool & matched) : _expected(expected), _matched(matched) {}
                   ss::future<consumption_result_type> operator()(tmp_buf buf) {
                       _matched = std::equal(buf.begin(), buf.end(), _expected.begin());
                       if (!_matched) {
                           return ss::make_ready_future<consumption_result_type>(stop_consuming_type({}));
                       }
                       _expected.remove_prefix(buf.size());
                       return ss::make_ready_future<consumption_result_type>(ss::continue_consuming{});
                   }
                   std::string_view _expected;
                     bool & _matched;
               };

               auto proc = external_process<consumer>::create_external_process({"/bin/echo", "-n", "hi"});
               proc.set_stdout_consumer( consumer { "hi", matched });
               BOOST_CHECK(!proc.is_running());
               proc.run().get();
               BOOST_CHECK(matched);
               BOOST_CHECK(!proc.is_running());
               return ss::make_ready_future<>();
           }).get();
}

SEASTAR_THREAD_TEST_CASE(run_long_process) {
    using namespace std::chrono_literals;
    auto proc = external_process<>::create_external_process({"/bin/sleep", "10"});
    BOOST_CHECK(!proc.is_running());
    auto start_time = std::chrono::high_resolution_clock::now();
    auto proc_fut = proc.run();
    ss::sleep(1s).get();
    BOOST_CHECK(proc.is_running());
    ss::sleep(5s).get();
    BOOST_CHECK(proc.is_running());
    proc_fut.get();
    BOOST_CHECK(!proc.is_running());
    auto end_time = std::chrono::high_resolution_clock::now();

    BOOST_CHECK(std::chrono::duration_cast<std::chrono::seconds>(end_time-start_time).count() >= 10);
}

SEASTAR_THREAD_TEST_CASE(run_long_process_and_terminate) {
    using namespace std::chrono_literals;
    auto proc = external_process<>::create_external_process({"/bin/sleep", "10"});
    BOOST_CHECK(!proc.is_running());
    auto proc_fut = proc.run();
    ss::sleep(1s).get();
    BOOST_CHECK(proc.is_running());
    proc.terminate(5s).get();
    BOOST_CHECK(!proc.is_running());
    BOOST_CHECK_EXCEPTION(proc_fut.get(), std::system_error, [](const std::system_error & e) {
        return e.code() == make_error_code(external_process_errc::exited_on_signal) &&
          std::string(e.what()) == std::string("Process /bin/sleep exited on signal 15: exited_on_signal");
    });
}

SEASTAR_THREAD_TEST_CASE(run_exit_on_code) {
    auto proc = external_process<>::create_external_process({"/bin/false"});
    BOOST_CHECK_EXCEPTION(proc.run().get(), std::system_error, [](const std::system_error & e) {
        return e.code() == make_error_code(external_process_errc::exited_non_zero) &&
          std::string(e.what()) == std::string("Process /bin/false exited with code 1: exited_non_zero");
    });
}

SEASTAR_THREAD_TEST_CASE(test_sigterm_ignored) {
    using namespace std::chrono_literals;
    const char * script_path = std::getenv("HANDLE_SIGTERM_SCRIPT");
    vassert(script_path, "Missing 'HANDLE_SIGTERM_SCRIPT' env variable");

    BOOST_REQUIRE_MESSAGE(ss::file_exists(script_path).get0(), std::string(script_path) + " does not exist");

    ss::do_with(bool(false), std::string(script_path), [](auto & matched, auto & script_path) {
        struct consumer {
            consumer(std::string_view expected, bool & matched) : _expected(expected), _matched(matched) {}
            ss::future<consumption_result_type> operator()(tmp_buf buf) {
                _matched = std::equal(buf.begin(), buf.end(), _expected.begin());
                if (!_matched) {
                    return ss::make_ready_future<consumption_result_type>(stop_consuming_type({}));
                }
                _expected.remove_prefix(buf.size());
                return ss::make_ready_future<consumption_result_type>(ss::continue_consuming{});
            }
            std::string_view _expected;
            bool & _matched;
        };

        auto proc = external_process<consumer>::create_external_process({script_path.c_str()});
        proc.set_stdout_consumer( consumer { "sigterm called", matched });
        BOOST_REQUIRE(!proc.is_running());
        auto proc_fut = proc.run();
        ss::sleep(100ms).get();
        if (proc_fut.failed())
        {
            BOOST_REQUIRE_NO_THROW(proc_fut.get());
        }
        BOOST_CHECK(proc.is_running());
        auto term_fut = proc.terminate(5s);
        ss::sleep(1s).get();
        BOOST_CHECK(proc.is_running());
        BOOST_CHECK(!term_fut.available() && !term_fut.failed());
        ss::sleep(5s).get();
        BOOST_CHECK(!proc.is_running());
        BOOST_CHECK(term_fut.available());
        BOOST_CHECK_EQUAL(term_fut.get0(), make_error_code(external_process_errc::success));

        BOOST_CHECK_EXCEPTION(proc_fut.get(), std::system_error, [&script_path](const std::system_error & e) {
            return e.code() == make_error_code(external_process_errc::exited_on_signal) &&
                   std::string(e.what()) == fmt::format("Process {} exited on signal 9: exited_on_signal", script_path);
        });

        BOOST_CHECK(matched);
        return ss::make_ready_future<>();
    }).get();
}
