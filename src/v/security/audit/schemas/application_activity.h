// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#pragma once

#include "security/audit/schemas/types.h"

#include <absl/container/flat_hash_map.h>

namespace security::audit {
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

    api_activity(
      activity_id activity_id,
      actor actor,
      api api,
      network_endpoint dst_endpoint,
      fragmented_vector<resource_detail> resources,
      api_activity::severity severity_id,
      network_endpoint src_endpoint,
      status_id status_id,
      ::time_t time)
      : activity_id(activity_id)
      , actor(std::move(actor))
      , api(std::move(api))
      , category_uid(category_uid::application_activity)
      , class_uid(class_uid::api_activity)
      , dst_endpoint(std::move(dst_endpoint))
      , metadata(ocsf_metadata)
      , resources(std::move(resources))
      , src_endpoint(std::move(src_endpoint))
      , severity_id(severity_id)
      , status_id(status_id)
      , time(time)
      , type_uid(int(this->class_uid) * 100 + int(this->activity_id)) {}

    friend void rjson_serialize(
      ::json::Writer<::json::StringBuffer>& w,
      const api_activity& api_activity);

private:
    activity_id activity_id;
    actor actor;
    api api;
    category_uid category_uid;
    class_uid class_uid;
    network_endpoint dst_endpoint;
    metadata metadata;
    absl::flat_hash_map<ss::sstring, ss::sstring> unmapped;
    fragmented_vector<resource_detail> resources;
    network_endpoint src_endpoint;
    severity severity_id;
    status_id status_id;
    long time;
    int type_uid;
};
inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const struct api_activity& api_activity) {
    w.StartObject();
    w.Key("activity_id");
    ::json::rjson_serialize(w, api_activity.activity_id);
    w.Key("actor");
    rjson_serialize(w, api_activity.actor);
    w.Key("api");
    rjson_serialize(w, api_activity.api);
    w.Key("category_uid");
    ::json::rjson_serialize(w, api_activity.category_uid);
    w.Key("class_uid");
    ::json::rjson_serialize(w, api_activity.class_uid);
    w.Key("dst_endpoint");
    rjson_serialize(w, api_activity.dst_endpoint);
    w.Key("metadata");
    rjson_serialize(w, api_activity.metadata);
    w.Key("resources");
    rjson_serialize(w, api_activity.resources);
    w.Key("severity_id");
    ::json::rjson_serialize(w, api_activity.severity_id);
    w.Key("src_endpoint");
    rjson_serialize(w, api_activity.src_endpoint);
    w.Key("status_id");
    ::json::rjson_serialize(w, api_activity.status_id);
    w.Key("time");
    ::json::rjson_serialize(w, api_activity.time);
    w.Key("type_uid");
    ::json::rjson_serialize(w, api_activity.type_uid);

    if (!api_activity.unmapped.empty()) {
        w.Key("unmapped");
        w.StartObject();
        for (const auto& iter : api_activity.unmapped) {
            w.Key(iter.first);
            ::json::rjson_serialize(w, iter.second);
        }
        w.EndObject();
    }
    w.EndObject();
}
} // namespace security::audit
