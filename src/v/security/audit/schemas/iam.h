// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0
#pragma once

#include "json/json.h"
#include "json/stringbuffer.h"

#include <security/audit/schemas/types.h>

namespace security::audit {

struct authentication {
    enum class activity_id : int {
        unknown = 0,
        logon = 1,
        logoff = 2,
        authentication_ticket = 3,
        service_ticket = 4,
        other = 99
    };
    enum class auth_protocol_id : int {
        unknown = 0,
        ntlm = 1,
        kerberos = 2,
        digest = 3,
        openid = 4,
        saml = 5,
        oauth_2_0 = 6,
        pap = 7,
        chap = 8,
        eap = 9,
        radius = 10,
        other = 99
    };
    enum class status_id : int {
        unknown = 0,
        success = 1,
        failure = 2,
        other = 99,
    };

    authentication(
      activity_id activity_id,
      std::variant<auth_protocol_id, ss::sstring> auth_protocol,
      network_endpoint dst_endpoint,
      bool is_cleartext,
      bool mfa,
      severity severity_id,
      network_endpoint src_endpoint,
      status_id status_id,
      long time,
      user user)
      : activity_id(activity_id)
      , category_uid(category_uid::iam)
      , class_uid(class_uid::authentication)
      , dst_endpoint(std::move(dst_endpoint))
      , is_cleartext(is_cleartext)
      , metadata(ocsf_metadata)
      , mfa(mfa)
      , severity_id(severity_id)
      , src_endpoint(std::move(src_endpoint))
      , status_id(status_id)
      , time(time)
      , type_uid(int(this->class_uid) * 100 + int(this->activity_id))
      , user(std::move(user))
      , _key(hash()) {
        ss::visit(
          auth_protocol,
          [this](enum auth_protocol_id auth_protocol_id) {
              this->auth_protocol = "";
              this->auth_protocol_id = auth_protocol_id;
          },
          [this](ss::sstring auth_protocol) {
              this->auth_protocol = std::move(auth_protocol);
              this->auth_protocol_id = auth_protocol_id::other;
          });
    }

    size_t key() const noexcept { return _key; }

    void increment(timestamp_t time) const noexcept {
        this->count++;
        this->end_time = time;
    }

    friend void rjson_serialize(
      ::json::Writer<::json::StringBuffer>&, const authentication&);

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& h,
      const authentication& a) {
        h.update(a.activity_id);
        h.update(a.auth_protocol);
        h.update(a.auth_protocol_id);
        h.update(a.category_uid);
        h.update(a.class_uid);
        h.update(a.dst_endpoint.ip);
        h.update(a.is_cleartext);
        h.update(a.mfa);
        h.update(a.severity_id);
        h.update(a.src_endpoint.ip);
        h.update(a.status_id);
        h.update(a.type_uid);
        h.update(a.user);
    }

private:
    activity_id activity_id;
    ss::sstring auth_protocol;
    auth_protocol_id auth_protocol_id;
    category_uid category_uid;
    class_uid class_uid;
    mutable long count;
    network_endpoint dst_endpoint;
    mutable timestamp_t end_time;
    bool is_cleartext;
    metadata metadata;
    bool mfa;
    severity severity_id;
    network_endpoint src_endpoint;
    timestamp_t start_time;
    status_id status_id;
    timestamp_t time;
    int type_uid;
    user user;
    size_t _key;

    size_t hash() const noexcept {
        size_t h = 0;

        boost::hash_combine(h, std::hash<int>()(int(activity_id)));
        boost::hash_combine(h, std::hash<ss::sstring>()(auth_protocol));
        boost::hash_combine(h, std::hash<int>()(int(auth_protocol_id)));
        boost::hash_combine(h, std::hash<int>()(int(category_uid)));
        boost::hash_combine(h, std::hash<int>()(int(class_uid)));
        boost::hash_combine(h, std::hash<ss::sstring>()(dst_endpoint.ip));
        boost::hash_combine(h, std::hash<bool>()(is_cleartext));
        boost::hash_combine(h, std::hash<bool>()(mfa));
        boost::hash_combine(h, std::hash<int>()(int(severity_id)));
        boost::hash_combine(h, std::hash<ss::sstring>()(src_endpoint.ip));
        boost::hash_combine(h, std::hash<int>()(int(status_id)));
        boost::hash_combine(h, std::hash<int>()(int(type_uid)));
        boost::hash_combine(h, std::hash<struct user>()(user));

        return h;
    }
};
inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const security::audit::authentication& authentication) {
    w.StartObject();

    w.Key("activity_id");
    rjson_serialize(w, authentication.activity_id);
    if (!authentication.auth_protocol.empty()) {
        w.Key("auth_protocol");
        rjson_serialize(w, authentication.auth_protocol);
    }

    w.Key("auth_protocol_id");
    rjson_serialize(w, authentication.auth_protocol_id);
    w.Key("category_uid");
    rjson_serialize(w, authentication.category_uid);
    w.Key("class_uid");
    rjson_serialize(w, authentication.class_uid);
    if (authentication.count > 1) {
        w.Key("count");
        rjson_serialize(w, authentication.count);
    }
    w.Key("dst_endpoint");
    rjson_serialize(w, authentication.dst_endpoint);
    if (authentication.count > 1) {
        w.Key("end_time");
        rjson_serialize(w, authentication.end_time);
    }
    w.Key("is_cleartext");
    rjson_serialize(w, authentication.is_cleartext);
    w.Key("metadata");
    rjson_serialize(w, authentication.metadata);
    w.Key("mfa");
    rjson_serialize(w, authentication.mfa);
    w.Key("severity_id");
    rjson_serialize(w, authentication.severity_id);
    w.Key("src_endpoint");
    rjson_serialize(w, authentication.src_endpoint);
    if (authentication.count > 1) {
        w.Key("start_time");
        rjson_serialize(w, authentication.start_time);
    }
    w.Key("status_id");
    rjson_serialize(w, authentication.status_id);
    w.Key("time");
    rjson_serialize(w, authentication.time);
    w.Key("type_uid");
    rjson_serialize(w, authentication.type_uid);
    w.Key("user");
    rjson_serialize(w, authentication.user);

    w.EndObject();
}
} // namespace security::audit
