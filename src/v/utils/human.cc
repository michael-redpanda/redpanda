// Copyright 2020 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "utils/human.h"

#include "seastarx.h"

#include <seastar/core/print.hh>

#include <absl/container/flat_hash_map.h>

#include <ostream>
#include <string>

namespace human {

namespace {
constexpr double KB = 1000.0;
constexpr double MB = 1000.0 * KB;
constexpr double GB = 1000.0 * MB;
constexpr double TB = 1000.0 * GB;
constexpr double PB = 1000.0 * TB;
const absl::flat_hash_map<char, double> golang_unit_map = {
  {'k', KB}, {'m', MB}, {'g', GB}, {'t', TB}, {'p', PB}};

const char* const human_units[6] = {"bytes", "KiB", "MiB", "GiB", "TiB", "PiB"};
const char* const golang_units[6] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
} // namespace

static std::ostream& bytes_helper(
  std::ostream& o, double val, double step, const char* const units[6]) {
    // static const char* units[] = {"bytes", "KiB", "MiB", "GiB", "TiB",
    // "PiB"};
    for (size_t i = 0; i < 6; ++i) {
        if (val <= step) {
            fmt::print(o, "{:03.3f}{}", val, units[i]);
            return o;
        }
        val /= step;
    }
    return o << val << "unknown_units";
}

std::ostream& operator<<(std::ostream& o, const ::human::latency& l) {
    static const char* units[] = {"μs", "ms", "secs"};
    static constexpr double step = 1000;
    auto x = l.value;
    for (size_t i = 0; i < 3; ++i) {
        if (x <= step) {
            fmt::print(o, "{:03.3f}{}", x, units[i]);
            return o;
        }
        x /= step;
    }
    return o << x << "unknown_units";
}
std::ostream& operator<<(std::ostream& o, const ::human::bytes& l) {
    static constexpr double step = 1024;
    return bytes_helper(o, l.value, step, human_units);
}

std::ostream& operator<<(std::ostream& o, const ::human::golang_bytes& l) {
    static constexpr double step = 1000;
    return bytes_helper(o, l.value, step, golang_units);
}

double golang_bytes::parse(const std::string_view& s) {
    auto pos = s.find_last_of("01234567890. ");
    if (pos == std::string::npos) {
        throw std::invalid_argument(
          fmt::format("does not contain a number: {}", s));
    }

    std::string_view num{}, sfx{};
    if (s[pos] != ' ') {
        num = s.substr(0, pos + 1);
        sfx = s.substr(pos + 1);
    } else {
        num = s.substr(0, pos);
        sfx = s.substr(pos + 1);
    }

    auto value = std::stod(std::string{num.data(), num.size()});

    if (value < 0) {
        throw std::invalid_argument(fmt::format("invalid size: {}", s));
    }

    if (sfx.empty()) {
        return value;
    }

    if (sfx.size() > 3) {
        throw std::invalid_argument(fmt::format("invalid suffix: {}", s));
    }

    if (tolower(sfx[0]) == 'b') {
        if (sfx.size() > 1) {
            throw std::invalid_argument(fmt::format("invalid suffix: {}", s));
        }
        return value;
    }

    try {
        value *= golang_unit_map.at(char(tolower(sfx[0])));
    } catch (...) {
        throw std::invalid_argument(fmt::format("invalid suffix: {}", s));
    }

    if (sfx.size() == 2 && tolower(sfx[1]) != 'b') {
        throw std::invalid_argument(fmt::format("invalid suffix: {}", s));
    } else if (
      sfx.size() == 3 && (tolower(sfx[1]) != 'i' || tolower(sfx[2]) != 'b')) {
        throw std::invalid_argument(fmt::format("invalid suffix: {}", s));
    }

    return value;
}

} // namespace human
