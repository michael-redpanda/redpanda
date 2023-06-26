// Copyright 2021 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "utils/human.h"

#include <boost/test/unit_test.hpp>
#include <fmt/format.h>
#include <fmt/ostream.h>

BOOST_AUTO_TEST_CASE(human_bytes) {
    BOOST_CHECK_EQUAL(fmt::format("{}", human::bytes(-1)), "-1.000bytes");
    BOOST_CHECK_EQUAL(fmt::format("{}", human::bytes(0)), "0.000bytes");
    BOOST_CHECK_EQUAL(fmt::format("{}", human::bytes(1)), "1.000bytes");
    BOOST_CHECK_EQUAL(fmt::format("{}", human::bytes(1024)), "1024.000bytes");
    BOOST_CHECK_EQUAL(fmt::format("{}", human::bytes(1025)), "1.001KiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::bytes(1UL << 20U)), "1024.000KiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::bytes(1UL << 30U)), "1024.000MiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::bytes(1UL << 40U)), "1024.000GiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::bytes(1UL << 50U)), "1024.000TiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::bytes(1UL << 60U)), "1024.000PiB");
}

BOOST_AUTO_TEST_CASE(golang_bytes) {
    BOOST_CHECK_EQUAL(fmt::format("{}", human::golang_bytes(-1)), "-1.000B");
    BOOST_CHECK_EQUAL(fmt::format("{}", human::golang_bytes(0)), "0.000B");
    BOOST_CHECK_EQUAL(fmt::format("{}", human::golang_bytes(1)), "1.000B");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::golang_bytes(1000)), "1000.000B");
    BOOST_CHECK_EQUAL(fmt::format("{}", human::golang_bytes(1001)), "1.001KiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::golang_bytes(1000UL * 1000UL)), "1000.000KiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::golang_bytes(1000UL * 1000UL * 1000UL)),
      "1000.000MiB");
    BOOST_CHECK_EQUAL(
      fmt::format("{}", human::golang_bytes(1000UL * 1000UL * 1000UL * 1000UL)),
      "1000.000GiB");
    BOOST_CHECK_EQUAL(
      fmt::format(
        "{}", human::golang_bytes(1000UL * 1000UL * 1000UL * 1000UL * 1000UL)),
      "1000.000TiB");
    BOOST_CHECK_EQUAL(
      fmt::format(
        "{}",
        human::golang_bytes(
          1000UL * 1000UL * 1000UL * 1000UL * 1000UL * 1000UL)),
      "1000.000PiB");
}

BOOST_AUTO_TEST_CASE(golang_bytes_parse) {
    BOOST_CHECK_EQUAL(human::golang_bytes(0), human::golang_bytes("0"));
    BOOST_CHECK_EQUAL(human::golang_bytes(0), human::golang_bytes("0b"));
    BOOST_CHECK_EQUAL(human::golang_bytes(1), human::golang_bytes("1B"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1), human::golang_bytes("1.000000 b"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1000), human::golang_bytes("1000.0B"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1001), human::golang_bytes("1.001KiB"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1000UL * 1000UL), human::golang_bytes("1000.000kb"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1000UL * 1000UL * 1000UL),
      human::golang_bytes("1000.000Mib"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1000UL * 1000UL * 1000UL * 1000UL),
      human::golang_bytes("1000.000gib"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1000UL * 1000UL * 1000UL * 1000UL * 1000UL),
      human::golang_bytes("1000.000tiB"));
    BOOST_CHECK_EQUAL(
      human::golang_bytes(1000UL * 1000UL * 1000UL * 1000UL * 1000UL * 1000UL),
      human::golang_bytes("1000.000PB"));
}

BOOST_AUTO_TEST_CASE(golang_bytes_parse_error) {
    BOOST_CHECK_EXCEPTION(
      human::golang_bytes("boo"),
      std::invalid_argument,
      [](const std::invalid_argument& e) {
          return std::string(e.what()) == "does not contain a number: boo";
      });
    BOOST_CHECK_EXCEPTION(
      human::golang_bytes("-1"),
      std::invalid_argument,
      [](const std::invalid_argument& e) {
          return std::string(e.what()) == "invalid size: -1";
      });
    BOOST_CHECK_EXCEPTION(
      human::golang_bytes("1ABCDEF"),
      std::invalid_argument,
      [](const std::invalid_argument& e) {
          return std::string(e.what()) == "invalid suffix: 1ABCDEF";
      });
    BOOST_CHECK_EXCEPTION(
      human::golang_bytes("1bI"),
      std::invalid_argument,
      [](const std::invalid_argument& e) {
          return std::string(e.what()) == "invalid suffix: 1bI";
      });
    BOOST_CHECK_EXCEPTION(
      human::golang_bytes("1O"),
      std::invalid_argument,
      [](const std::invalid_argument& e) {
          return std::string(e.what()) == "invalid suffix: 1O";
      });
    BOOST_CHECK_EXCEPTION(
      human::golang_bytes("1KS"),
      std::invalid_argument,
      [](const std::invalid_argument& e) {
          return std::string(e.what()) == "invalid suffix: 1KS";
      });
    BOOST_CHECK_EXCEPTION(
      human::golang_bytes("1kiS"),
      std::invalid_argument,
      [](const std::invalid_argument& e) {
          return std::string(e.what()) == "invalid suffix: 1kiS";
      });
}
