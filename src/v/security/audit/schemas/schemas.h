// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0
#pragma once

#include "security/audit/schemas/application_activity.h"
#include "security/audit/schemas/iam.h"

namespace security::audit {

template<typename T>
ss::sstring rjson_serialize(const T& v) {
    ::json::StringBuffer str_buf;
    ::json::Writer<::json::StringBuffer> wrt(str_buf);

    using ::json::rjson_serialize;
    using ::security::audit::rjson_serialize;

    rjson_serialize(wrt, v);

    return ss::sstring(str_buf.GetString(), str_buf.GetSize());
}

template<typename T>
concept KeyedAuditEvent = requires(T e) {
    { e.key() } -> std::convertible_to<size_t>;
};

template<typename T>
concept IncrementalEvent = requires(T e, timestamp_t t) {
    { e.increment(t) };
    { T::count } -> std::convertible_to<long>;
};
struct audit_event {
    using audit_events
      = std::variant<api_activity, application_lifecycle, authentication>;

    audit_events event;
    size_t key;

    audit_event() = delete;

    template<KeyedAuditEvent T>
    static audit_event create_audit_event(T&& event) {
        auto key = event.key();
        return audit_event{event, key};
    }

    void increment(timestamp_t t) const {
        std::visit(
          [t]<typename T>(const T& e) {
              if constexpr (IncrementalEvent<T>) {
                  e.increment(t);
              }
          },
          event);
    }

    long count() const {
        return std::visit(
          []<typename T>(const T& e) -> long {
              if constexpr (IncrementalEvent<T>) {
                  return e.count;
              } else {
                  return 1;
              }
          },
          event);
    }

    ss::sstring rjson_serialize() const {
        return std::visit(
          [](auto& e) -> ss::sstring {
              return ::security::audit::rjson_serialize(e);
          },
          event);
    }

private:
    template<typename T>
    audit_event(T&& event, size_t key)
      : event(std::move(event))
      , key(key) {}
};
} // namespace security::audit
