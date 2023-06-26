/*
 * Copyright 2020 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#pragma once

#include <iosfwd>
#include <string_view>

/// \brief usage: fmt::format("{}", human::bytes(3234.234));
//  or fmt::format("{}", human::latency(321.048));
namespace human {
struct bytes {
    explicit bytes(double x)
      : value(x) {}
    double value;
    friend std::ostream& operator<<(std::ostream& o, const bytes&);
};
struct latency {
    explicit latency(double x)
      : value(x) {}
    double value;
    friend std::ostream& operator<<(std::ostream& o, const latency&);
};

struct golang_bytes {
    explicit golang_bytes(double x)
      : value(x) {}
    explicit golang_bytes(const std::string_view& s)
      : value(golang_bytes::parse(s)) {}
    double value;
    friend std::ostream& operator<<(std::ostream& o, const golang_bytes&);
    friend std::istream& operator>>(std::istream& i, golang_bytes&);
    static double parse(const std::string_view& s);

    friend bool operator==(const golang_bytes& lhs, const golang_bytes& rhs) {
        // std::numeric_limits<double>::epsilon() is too small for the float
        // correction.  Instead, using 1E-4 as the numbers printed are within
        // that fraction.
        static constexpr double epsilon = 0.0001;
        return fabs(lhs.value - rhs.value) <= epsilon;
    }

    friend bool operator<(const golang_bytes& lhs, const golang_bytes& rhs) {
        return lhs.value < rhs.value;
    }
};
} // namespace human
