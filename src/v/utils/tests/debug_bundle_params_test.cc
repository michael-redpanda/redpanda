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

#include "utils/debug_bundle.h"

#include <boost/test/unit_test.hpp>
#include <fmt/chrono.h>

BOOST_AUTO_TEST_CASE(validate_parameters_stream) {
    using namespace std::chrono_literals;
    auto username = "testusername";
    auto password = "testpassword";
    auto mechanism = "SASL-SCRAM-256";
    constexpr auto expected_syslog_time_format_string
      = "\"{:%Y-%m-%d %H:%M:%S}\"";
    debug_bundle::debug_bundle::debug_bundle_credentials creds{
      .username = username,
      .password = password,
      .mechanism = mechanism,
      .use_tls = true};

    auto now = std::chrono::system_clock::now();
    auto now_fmt = fmt::format(
      expected_syslog_time_format_string, fmt::localtime(now));
    auto metrics_interval = 5s;
    auto size = human::golang_bytes{1000};

    debug_bundle::debug_bundle::debug_bundle_parameters params{
      .logs_since = now,
      .logs_until = now,
      .logs_size_limit = size,
      .metrics_interval = metrics_interval,
      .credentials = creds};

    BOOST_CHECK_EQUAL(
      fmt::format(
        " --logs-since {} --logs-until {} --logs-size-limit {} "
        "--metrics-interval {} --username {} --password ******** --mechanism "
        "{} --tls-enabled",
        now_fmt,
        now_fmt,
        size,
        metrics_interval,
        username,
        mechanism),
      fmt::format("{}", params));
}

BOOST_AUTO_TEST_CASE(validate_parameters_vector) {
    using namespace std::chrono_literals;
    auto username = "testusername";
    auto password = "testpassword";
    auto mechanism = "SASL-SCRAM-256";
    constexpr auto expected_syslog_time_format_string
      = "\"{:%Y-%m-%d %H:%M:%S}\"";
    debug_bundle::debug_bundle::debug_bundle_credentials creds{
      .username = username,
      .password = password,
      .mechanism = mechanism,
      .use_tls = true};

    auto now = std::chrono::system_clock::now();
    auto now_fmt = fmt::format(
      expected_syslog_time_format_string, fmt::localtime(now));
    auto metrics_interval = 5s;
    auto size = human::golang_bytes{1000};

    debug_bundle::debug_bundle::debug_bundle_parameters params{
      .logs_since = now,
      .logs_until = now,
      .logs_size_limit = size,
      .metrics_interval = metrics_interval,
      .credentials = creds};

    std::vector<ss::sstring> expected{
      "--logs-since",
      now_fmt,
      "--logs-until",
      now_fmt,
      "--logs-size-limit",
      fmt::format("{}", size),
      "--metrics-interval",
      fmt::format("{}", metrics_interval),
      "--username",
      username,
      "--password",
      password,
      "--mechanism",
      mechanism,
      "--tls-enabled"};

    std::vector<ss::sstring> test;

    params(test);

    BOOST_CHECK_EQUAL(expected, test);
}
