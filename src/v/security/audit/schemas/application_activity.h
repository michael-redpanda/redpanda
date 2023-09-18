// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#pragma once

#include "hashing/xx.h"
#include "types.h"
#include "utils/named_type.h"

namespace security::audit {

using timestamp_t = named_type<long, struct timestamp_t_type>;
using type_uid = named_type<long, struct type_uid_type>;

struct api_activity {
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

    struct unmapped {
        struct acl_authorization {
            ss::sstring host;
            ss::sstring op;
            ss::sstring permission_type;
            ss::sstring principal;
        } acl_authorization;

        struct resource {
            ss::sstring name;
            ss::sstring pattern;
            ss::sstring type;
        } resource;

        friend void tag_invoke(
          tag_t<incremental_xxhash64_tag>,
          incremental_xxhash64& h,
          const unmapped& u) {
            h.update(u.acl_authorization.host);
            h.update(u.acl_authorization.op);
            h.update(u.acl_authorization.permission_type);
            h.update(u.acl_authorization.principal);
            h.update(u.resource.name);
            h.update(u.resource.pattern);
            h.update(u.resource.type);
        }
    };

    api_activity() = delete;

    api_activity(
      activity_id activity_id,
      actor actor,
      api api,
      network_endpoint dst_endpoint,
      fragmented_vector<resource_detail> resources,
      severity severity_id,
      network_endpoint src_endpoint,
      status_id status_id,
      timestamp_t time,
      unmapped unmapped)
      : activity_id(std::move(activity_id))
      , actor(std::move(actor))
      , api(std::move(api))
      , dst_endpoint(std::move(dst_endpoint))
      , end_time(time)
      , metadata(ocsf_metadata)
      , resources(std::move(resources))
      , severity_id(severity_id)
      , src_endpoint(src_endpoint)
      , start_time(time)
      , status_id(status_id)
      , time(time)
      , type_uid(
          type_uid::type(this->class_uid) * 100L
          + type_uid::type(this->activity_id))
      , unmapped(std::move(unmapped)) {}

    uint64_t hash() const noexcept {
        incremental_xxhash64 hash{};
        hash.update(*this);
        auto val = hash.digest();
        return val;
    }

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const api_activity& api_activity) {
        hash.update(api_activity.activity_id);
        hash.update(api_activity.actor);
        hash.update(api_activity.api);
        hash.update(api_activity.category_uid);
        hash.update(api_activity.class_uid);
        hash.update(api_activity.dst_endpoint.ip);
        for (const auto& r : api_activity.resources) {
            hash.update(r);
        }
        hash.update(api_activity.src_endpoint.ip);
        hash.update(api_activity.status_id);
        hash.update(api_activity.type_uid);
        hash.update(api_activity.unmapped);
    }

    void increment(timestamp_t time) const noexcept {
        this->count++;
        this->end_time = time;
    }

    activity_id activity_id;
    actor actor;
    api api;
    category_uid category_uid{category_uid::application_activity};
    class_uid class_uid{class_uid::api_activity};
    // Count and end_time are mutable because they are not part of the
    // hash of the item
    mutable long count{1};
    network_endpoint dst_endpoint;
    mutable timestamp_t end_time;
    metadata metadata;
    fragmented_vector<resource_detail> resources;
    severity severity_id;

    network_endpoint src_endpoint;
    timestamp_t start_time;
    status_id status_id;
    timestamp_t time;
    type_uid type_uid;
    unmapped unmapped;

    friend void rjson_serialize(
      ::json::Writer<::json::StringBuffer>& w,
      const api_activity& api_activity);
};

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const struct api_activity& api_activity) {
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
    w.Key("unmapped");
    w.StartObject();
    w.Key("acl_authorization");
    w.StartObject();
    w.Key("host");
    ::json::rjson_serialize(w, api_activity.unmapped.acl_authorization.host);
    w.Key("op");
    ::json::rjson_serialize(w, api_activity.unmapped.acl_authorization.op);
    w.Key("permission_type");
    ::json::rjson_serialize(
      w, api_activity.unmapped.acl_authorization.permission_type);
    w.Key("principal");
    ::json::rjson_serialize(
      w, api_activity.unmapped.acl_authorization.principal);
    w.EndObject();
    w.Key("resource");
    w.StartObject();
    w.Key("name");
    ::json::rjson_serialize(w, api_activity.unmapped.resource.name);
    w.Key("pattern");
    ::json::rjson_serialize(w, api_activity.unmapped.resource.pattern);
    w.Key("type");
    ::json::rjson_serialize(w, api_activity.unmapped.resource.type);
    w.EndObject();
    w.EndObject();
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

static inline struct api_activity::unmapped
result_to_unmapped(const security::auth_result& result) {
    struct api_activity::unmapped rv;

    if (result.acl) {
        rv.acl_authorization.principal = fmt::format(
          "{}", result.acl->get().principal());
        rv.acl_authorization.host = fmt::format("{}", result.acl->get().host());
        rv.acl_authorization.op = fmt::format(
          "{}", result.acl->get().operation());
    }
    rv.acl_authorization.permission_type = result.authorized ? "AUTHORIZED"
                                                             : "DENIED";

    if (result.resource_pattern) {
        rv.resource.name = result.resource_pattern->get().name();
        rv.resource.pattern = fmt::format(
          "{}", result.resource_pattern->get().pattern());
        rv.resource.type = fmt::format(
          "{}", result.resource_pattern->get().resource());
    }

    return rv;
};

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
            .type = fmt::format("{}", security::get_resource_type<T>())};
      });

    return {
      crud,
      result_to_actor(result),
      api{.operation = ss::sstring{op_name.data(), op_name.size()}},
      network_endpoint{
        .ip = fmt::format("{}", local_address.addr()),
        .port = local_address.port(),
      },
      std::move(resource_details),
      api_activity::severity::informational,
      network_endpoint{
        .ip = fmt::format("{}", result.host.address()),
      },
      result.authorized ? api_activity::status_id::success
                        : api_activity::status_id::failure,
      timestamp_t{std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count()},
      result_to_unmapped(result)};
}

} // namespace security::audit
