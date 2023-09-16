// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#pragma once

#include "security/acl.h"
#include "security/audit/schemas/types.h"
#include "security/authorizer.h"

#include <absl/container/flat_hash_map.h>

#include <chrono>

namespace security::audit {

struct api_activity {
    using timestamp_clock = std::chrono::system_clock;
    enum class activity_id : int {
        unknown = 0,
        create = 1,
        read = 2,
        update = 3,
        delete_id = 4,
        other = 99,
    };

    enum class severity : int {
        unknown = 0,
        informational = 1,
        low = 2,
        medium = 3,
        high = 4,
        critical = 5,
        fatal = 6,
        other = 99,
    };

    enum class status_id : int {
        unknown = 0,
        success = 1,
        failure = 2,
        other = 99,
    };

    api_activity() = delete;

    api_activity(
      std::optional<security::acl_entry>&& acl,
      activity_id activity_id,
      actor actor,
      api api,
      network_endpoint dst_endpoint,
      std::optional<security::resource_pattern>&& resource_pattern,
      fragmented_vector<resource_detail>&& resources,
      api_activity::severity severity_id,
      network_endpoint src_endpoint,
      status_id status_id,
      ::time_t time)
      : acl(std::move(acl))
      , activity_id(activity_id)
      , actor(std::move(actor))
      , api(std::move(api))
      , category_uid(category_uid::application_activity)
      , class_uid(class_uid::api_activity)
      , dst_endpoint(std::move(dst_endpoint))
      , metadata(ocsf_metadata)
      , resource_pattern(std::move(resource_pattern))
      , resources(std::move(resources))
      , src_endpoint(std::move(src_endpoint))
      , severity_id(severity_id)
      , start_time(time)
      , status_id(status_id)
      , time(time)
      , type_uid(int(this->class_uid) * 100 + int(this->activity_id)) {}

    friend void rjson_serialize(
      ::json::Writer<::json::StringBuffer>& w,
      const api_activity& api_activity);

    friend bool operator==(const api_activity&, const api_activity&);

    struct equal {
        using is_transparant = void;
        bool operator()(const api_activity& lhs, const api_activity& rhs) {
            return lhs == rhs;
        }
    };

    void increment(long time) noexcept {
        this->count++;
        this->end_time = time;
    }

    size_t get_count() const noexcept { return this->count; }

    std::optional<security::acl_entry> acl;
    activity_id activity_id;
    actor actor;
    api api;
    category_uid category_uid;
    class_uid class_uid;
    size_t count{1};
    network_endpoint dst_endpoint;
    long end_time{0};
    metadata metadata;
    std::optional<security::resource_pattern> resource_pattern;
    fragmented_vector<resource_detail> resources;
    network_endpoint src_endpoint;
    severity severity_id;
    long start_time{0};
    status_id status_id;
    long time;
    int type_uid;
};

inline bool operator==(const api_activity& lhs, const api_activity& rhs) {
    return lhs.acl == rhs.acl && lhs.activity_id == rhs.activity_id
           && lhs.actor == rhs.actor && lhs.api == rhs.api
           && lhs.category_uid == rhs.category_uid
           && lhs.class_uid == rhs.class_uid
           && lhs.dst_endpoint == rhs.dst_endpoint
           && lhs.metadata == rhs.metadata
           && lhs.resource_pattern == rhs.resource_pattern
           && lhs.resources == rhs.resources
           && lhs.src_endpoint.ip == rhs.src_endpoint.ip
           && lhs.severity_id == rhs.severity_id
           && lhs.status_id == rhs.status_id && lhs.type_uid == rhs.type_uid;
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const struct security::audit::api_activity& api_activity) {
    w.StartObject();
    w.Key("activity_id");
    rjson_serialize(w, api_activity.activity_id);
    w.Key("actor");
    rjson_serialize(w, api_activity.actor);
    w.Key("api");
    rjson_serialize(w, api_activity.api);
    w.Key("category_uid");
    rjson_serialize(w, api_activity.category_uid);
    w.Key("class_uid");
    rjson_serialize(w, api_activity.class_uid);
    if (api_activity.count > 1) {
        w.Key("count");
        rjson_serialize(w, api_activity.count);
    }
    w.Key("dst_endpoint");
    rjson_serialize(w, api_activity.dst_endpoint);
    if (api_activity.count > 1) {
        w.Key("end_time");
        rjson_serialize(w, api_activity.end_time);
    }
    w.Key("metadata");
    rjson_serialize(w, api_activity.metadata);
    w.Key("resources");
    rjson_serialize(w, api_activity.resources);
    w.Key("severity_id");
    rjson_serialize(w, api_activity.severity_id);
    w.Key("src_endpoint");
    rjson_serialize(w, api_activity.src_endpoint);
    if (api_activity.count > 1) {
        w.Key("start_time");
        rjson_serialize(w, api_activity.start_time);
    }
    w.Key("status_id");
    rjson_serialize(w, api_activity.status_id);
    w.Key("time");
    rjson_serialize(w, api_activity.time);
    w.Key("type_uid");
    rjson_serialize(w, api_activity.type_uid);
    w.EndObject();
}

static inline enum api_activity::activity_id
op_to_crud(security::acl_operation op) {
    static const absl::flat_hash_map<
      security::acl_operation,
      enum api_activity::activity_id>
      op_to_crud_map {
          {security::acl_operation::read, api_activity::activity_id::read},
          {security::acl_operation::write, api_activity::activity_id::update},
          {security::acl_operation::create, api_activity::activity_id::create},
          {security::acl_operation::remove,
           api_activity::activity_id::delete_id},
          {security::acl_operation::alter, api_activity::activity_id::update},
          {security::acl_operation::alter_configs,
           api_activity::activity_id::update},
          {security::acl_operation::describe, api_activity::activity_id::read},
          {security::acl_operation::describe_configs,
           api_activity::activity_id::read},
      };

    auto result = op_to_crud_map.find(op);
    vassert(result != op_to_crud_map.end(), "Invalid operation {}", op);
    return result->second;
}
template<typename T>
api_activity create_api_activity(
  const std::string_view& op_name,
  security::acl_operation op,
  const security::auth_result& result,
  const ss::socket_address& local_address,
  const fragmented_vector<T>& resources) {
    auto crud = op_to_crud(op);
    fragmented_vector<resource_detail> resource_details;
    std::transform(
      resources.begin(),
      resources.end(),
      std::back_inserter(resource_details),
      [](auto&& item) -> resource_detail {
          return {
            .name = fmt::format("{}", item()),
            .type = fmt::format("{}", security::get_resource_type<T>()),
          };
      });

    return {
      result.acl,
      crud,
      result_to_actor(result),
      api{.operation = ss::sstring{op_name.data(), op_name.size()}},
      network_endpoint{
        .ip = fmt::format("{}", local_address.addr()),
        .port = local_address.port()},
      result.resource_pattern,
      std::move(resource_details),
      api_activity::severity::informational,
      network_endpoint{
        .ip = fmt::format("{}", result.host.address()),
      },
      result.authorized ? api_activity::status_id::success
                        : api_activity::status_id::failure,
      std::chrono::duration_cast<std::chrono::milliseconds>(
        api_activity::timestamp_clock::now().time_since_epoch())
        .count()};
}

} // namespace security::audit

namespace json {
inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::acl_principal& principal) {
    rjson_serialize(
      w,
      std::string_view{
        fmt::format("{}:{}", principal.type(), principal.name())});
}

inline void
rjson_serialize(Writer<StringBuffer>& w, const security::acl_host& host) {
    if (!host.address().has_value()) {
        rjson_serialize(w, "*");
    } else {
        rjson_serialize(
          w, std::string_view{fmt::format("{}", host.address().value())});
    }
}

inline void
rjson_serialize(Writer<StringBuffer>& w, const security::acl_operation& op) {
    rjson_serialize(w, std::string_view{fmt::format("{}", op)});
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::acl_permission& permission) {
    rjson_serialize(w, std::string_view{fmt::format("{}", permission)});
}

inline void
rjson_serialize(Writer<StringBuffer>& w, const security::acl_entry& acl) {
    w.StartObject();
    w.Key("principal");
    rjson_serialize(w, acl.principal());
    w.Key("host");
    rjson_serialize(w, acl.host());
    w.Key("op");
    rjson_serialize(w, acl.operation());
    w.Key("permission_type");
    rjson_serialize(w, acl.permission());
    w.EndObject();
}
} // namespace json
