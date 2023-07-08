// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "random/generators.h"
#include "utils/debug_bundle.h"

#include <seastar/testing/thread_test_case.hh>
#include <seastar/util/defer.hh>

const char* get_rpk_shim_script() {
    const char* script_path = std::getenv("RPK_SHIM_SCRIPT");
    vassert(script_path, "Missing 'RPK_SHIM_SCRIPT'");

    return script_path;
}

ss::future<ss::sstring> create_random_directory(std::string_view base_path) {
    const auto dir_num = random_generators::get_int<int64_t>(2000, 4000);
    auto dir = fmt::format("{}/rpk-debug-bundle-{}", base_path, dir_num);

    co_await ss::make_directory(std::string_view{dir});
    co_await ss::sync_directory(std::string_view{dir});
    co_return ss::sstring{dir};
}

SEASTAR_THREAD_TEST_CASE(rpk_debug_bundle_run) {
    using namespace std::chrono_literals;
    auto script_path = get_rpk_shim_script();
    auto dir = create_random_directory("/tmp").get0();
    auto debug_bundle_cleanup_period = 1s;
    auto debug_bundle_ttl = 5s;

    ss::sharded<debug_bundle::debug_bundle> bundle;
    ss::deferred_action<std::function<void()>> destroy_bundle(
      [&bundle] { return bundle.stop().get(); });

    bundle
      .start(
        config::mock_binding<std::filesystem::path>(std::filesystem::path{dir}),
        config::mock_binding<std::filesystem::path>(script_path),
        config::mock_binding<std::chrono::seconds>(
          std::chrono::seconds{debug_bundle_cleanup_period}),
        config::mock_binding<std::chrono::seconds>(
          std::chrono::seconds{debug_bundle_ttl}))
      .get();

    auto result = bundle.local().create_debug_bundle(
      debug_bundle::debug_bundle::debug_bundle_parameters{});
    ss::sleep(1s).get();
    BOOST_CHECK(bundle.local().is_running().get());
    auto process_result = result.get0();
    BOOST_REQUIRE(process_result.has_value());
    auto name = process_result.value();
    BOOST_CHECK(ss::file_exists(name).get0());
    auto bundles = bundle.local().bundles().get0();
    BOOST_REQUIRE_EQUAL(bundles.size(), 1);
    BOOST_CHECK_EQUAL(bundles[0], name);
    ss::sleep(6s).get();
    BOOST_CHECK(!ss::file_exists(name).get0());
    bundles = bundle.local().bundles().get0();
    BOOST_CHECK(bundles.empty());
}

SEASTAR_THREAD_TEST_CASE(rpk_debug_bundle_interrupt) {
    using namespace std::chrono_literals;
    auto script_path = get_rpk_shim_script();
    auto dir = create_random_directory("/tmp").get0();
    auto debug_bundle_cleanup_period = 1s;
    auto debug_bundle_ttl = 5s;

    ss::sharded<debug_bundle::debug_bundle> bundle;
    ss::deferred_action<std::function<void()>> destroy_bundle(
      [&bundle] { return bundle.stop().get(); });

    bundle
      .start(
        config::mock_binding<std::filesystem::path>(std::filesystem::path{dir}),
        config::mock_binding<std::filesystem::path>(script_path),
        config::mock_binding<std::chrono::seconds>(
          std::chrono::seconds{debug_bundle_cleanup_period}),
        config::mock_binding<std::chrono::seconds>(
          std::chrono::seconds{debug_bundle_ttl}))
      .get();

    auto result = bundle.local().create_debug_bundle(
      debug_bundle::debug_bundle::debug_bundle_parameters{});
    ss::sleep(1s).get();
    BOOST_CHECK(bundle.local().is_running().get());
    BOOST_CHECK(!bundle.local().stop_debug_bundle().get0());
    BOOST_CHECK_EXCEPTION(
      result.get(),
      std::system_error,
      [&script_path](const std::system_error& e) {
          return e.code()
                   == make_error_code(external_process_errc::exited_on_signal)
                 && std::string(e.what())
                      == fmt::format(
                        "Process {} exited on signal 15: exited_on_signal",
                        script_path);
      });
    auto bundles = bundle.local().bundles().get0();
    BOOST_CHECK(bundles.empty());
}

SEASTAR_THREAD_TEST_CASE(rpk_debug_bundle_erase) {
    using namespace std::chrono_literals;
    auto script_path = get_rpk_shim_script();
    auto dir = create_random_directory("/tmp").get0();
    auto debug_bundle_cleanup_period = 1s;
    auto debug_bundle_ttl = 5s;

    ss::sharded<debug_bundle::debug_bundle> bundle;
    ss::deferred_action<std::function<void()>> destroy_bundle(
      [&bundle] { return bundle.stop().get(); });

    bundle
      .start(
        config::mock_binding<std::filesystem::path>(std::filesystem::path{dir}),
        config::mock_binding<std::filesystem::path>(script_path),
        config::mock_binding<std::chrono::seconds>(
          std::chrono::seconds{debug_bundle_cleanup_period}),
        config::mock_binding<std::chrono::seconds>(
          std::chrono::seconds{debug_bundle_ttl}))
      .get();

    auto result = bundle.local().create_debug_bundle(
      debug_bundle::debug_bundle::debug_bundle_parameters{});
    ss::sleep(1s).get();
    BOOST_CHECK(bundle.local().is_running().get());
    auto process_result = result.get0();
    BOOST_REQUIRE(process_result.has_value());
    auto name = process_result.value();
    BOOST_CHECK(ss::file_exists(name).get0());
    auto bundles = bundle.local().bundles().get0();
    BOOST_REQUIRE_EQUAL(bundles.size(), 1);
    BOOST_CHECK_EQUAL(bundles[0], name);
    BOOST_CHECK(!bundle.local().delete_bundle(name).get0());
    BOOST_CHECK(bundle.local().bundles().get0().empty());
}
