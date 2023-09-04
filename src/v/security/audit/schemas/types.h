// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "json/json.h"
#include "json/stringbuffer.h"
#include "seastarx.h"

#pragma once

namespace security::audit {

static constexpr std::string_view ocsf_api_version = "1.0.0";

enum class category_uid : int {
    system_activity = 1,
    findings = 2,
    iam = 3,
    network_activity = 4,
    discovery = 5,
    application_activity = 6
};

enum class class_uid : int {
    file_system_activity = 1001,
    kernel_extension_activity = 1002,
    kernel_activity = 1003,
    memory_activity = 1004,
    module_activity = 1005,
    scheduled_job_activity = 1006,
    process_activity = 1007,
    security_finding = 2001,
    account_change = 3001,
    authentication = 3002,
    authorize_session = 3003,
    entity_management = 3004,
    user_access_management = 3005,
    group_management = 3006,
    network_activity = 4001,
    http_activity = 4002,
    dns_activity = 4003,
    dhcp_activity = 4004,
    rdp_activity = 4005,
    smb_activity = 4006,
    ssh_activity = 4007,
    ftp_activity = 4008,
    email_activity = 4009,
    network_file_activity = 4010,
    email_file_activity = 4011,
    email_url_activity = 4012,
    device_inventory_info = 5001,
    device_config_state = 5002,
    web_resource_activity = 6001,
    application_lifecycle = 6002,
    api_activity = 6003,
    web_resource_access_activity = 6004
};

struct product {
    ss::sstring name;
    ss::sstring vendor_name;
    ss::sstring version;
};

static const product redpanda_product = {
  .name = "Redpanda",
  .vendor_name = "Redpanda Data, Inc",
  .version = "FILL THIS IN"};

struct api {
    ss::sstring operation;
};

struct metadata {
    ss::sstring version;
    product product;
};

static const metadata ocsf_metadata = {
  .version = ss::sstring(ocsf_api_version.data(), ocsf_api_version.size()),
  .product = redpanda_product};

struct network_endpoint {
    std::vector<ss::sstring> intermediate_ips;
    ss::sstring ip;
    ss::sstring name;
    uint16_t port;
    ss::sstring uid;
};

struct policy {
    ss::sstring name;
    ss::sstring desc;
};

struct authorization_result {
    ss::sstring decision;
    policy policy;
};

struct user {
    enum class type : int {
        unknown = 0,
        user = 1,
        admin = 2,
        system = 3,
        other = 99
    };

    ss::sstring credential_uid;
    ss::sstring domain;
    ss::sstring name;
    type type_id;
};

struct actor {
    std::vector<authorization_result> authorizations;
    user user;
};

struct resource_detail {
    ss::sstring name;
    ss::sstring type;
};

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w, const security::audit::api& api) {
    w.StartObject();
    w.Key("operation");
    ::json::rjson_serialize(w, api.operation);
    w.EndObject();
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const security::audit::product& product) {
    w.StartObject();
    w.Key("name");
    ::json::rjson_serialize(w, product.name);
    w.Key("vendor_name");
    ::json::rjson_serialize(w, product.vendor_name);
    w.Key("version");
    ::json::rjson_serialize(w, product.version);
    w.EndObject();
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const security::audit::metadata& metadata) {
    w.StartObject();
    w.Key("version");
    ::json::rjson_serialize(w, metadata.version);
    w.Key("product");
    rjson_serialize(w, metadata.product);
    w.EndObject();
    ;
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const security::audit::network_endpoint& endpoint) {
    w.StartObject();
    if (!endpoint.intermediate_ips.empty()) {
        w.Key("intermediate_ips");
        ::json::rjson_serialize(w, endpoint.intermediate_ips);
    }
    w.Key("ip");
    ::json::rjson_serialize(w, endpoint.ip);
    if (!endpoint.name.empty()) {
        w.Key("name");
        ::json::rjson_serialize(w, endpoint.name);
    }
    w.Key("port");
    ::json::rjson_serialize(w, endpoint.port);
    if (!endpoint.uid.empty()) {
        w.Key("uid");
        ::json::rjson_serialize(w, endpoint.uid);
    }
    w.EndObject();
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w, const security::audit::policy& p) {
    w.StartObject();
    w.Key("name");
    ::json::rjson_serialize(w, p.name);
    w.Key("desc");
    ::json::rjson_serialize(w, p.desc);
    w.EndObject();
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const security::audit::authorization_result& authz) {
    w.StartObject();
    w.Key("decision");
    ::json::rjson_serialize(w, authz.decision);
    w.Key("policy");
    rjson_serialize(w, authz.policy);
    w.EndObject();
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w, const security::audit::user& user) {
    w.StartObject();
    if (!user.credential_uid.empty()) {
        w.Key("credential_uid");
        ::json::rjson_serialize(w, user.credential_uid);
    }
    if (!user.domain.empty()) {
        w.Key("domain");
        ::json::rjson_serialize(w, user.domain);
    }
    w.Key("type_id");
    ::json::rjson_serialize(w, user.type_id);
    w.Key("name");
    ::json::rjson_serialize(w, user.name);
    w.EndObject();
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const security::audit::actor& actor) {
    w.StartObject();
    w.Key("authorizations");
    ::json::rjson_serialize(w, actor.authorizations);
    w.Key("user");
    rjson_serialize(w, actor.user);
    w.EndObject();
}

inline void rjson_serialize(
  ::json::Writer<::json::StringBuffer>& w,
  const security::audit::resource_detail& resource) {
    w.StartObject();
    w.Key("name");
    ::json::rjson_serialize(w, resource.name);
    w.Key("type");
    ::json::rjson_serialize(w, resource.type);
    w.EndObject();
}

} // namespace security::audit
