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
#include "security/authorizer.h"
#include "version.h"

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

    friend bool operator==(const product&, const product&) = default;
};

static const product redpanda_product = {
  .name = "Redpanda",
  .vendor_name = "Redpanda Data, Inc",
  .version = ss::sstring{redpanda_git_version()}};

struct api {
    ss::sstring operation;

    friend bool operator==(const api&, const api&) = default;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const api& a) {
        hash.update(a.operation);
    }
};

struct metadata {
    ss::sstring version;
    product product;

    friend bool operator==(const metadata&, const metadata&) = default;
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

    friend bool operator==(const network_endpoint&, const network_endpoint&)
      = default;
};

struct policy {
    ss::sstring name;
    ss::sstring desc;

    friend bool operator==(const policy&, const policy&) = default;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const policy& p) {
        hash.update(p.name);
        hash.update(p.desc);
    }
};

struct authorization_result {
    ss::sstring decision;
    policy policy;

    friend bool
    operator==(const authorization_result&, const authorization_result&)
      = default;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const authorization_result& result) {
        hash.update(result.decision);
        hash.update(result.policy);
    }
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

    friend bool operator==(const user&, const user&) = default;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const user& u) {
        hash.update(u.credential_uid);
        hash.update(u.domain);
        hash.update(u.name);
        hash.update(u.type_id);
    }
};

struct actor {
    std::vector<authorization_result> authorizations;
    user user;

    friend bool operator==(const actor&, const actor&);

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const actor& a) {
        for (const auto& authzs : a.authorizations) {
            hash.update(authzs);
        }

        hash.update(a.user);
    }
};

inline bool operator==(const actor& lhs, const actor& rhs) {
    return lhs.authorizations == rhs.authorizations && lhs.user == rhs.user;
}

struct resource_detail {
    ss::sstring name;
    ss::sstring type;

    friend bool operator==(const resource_detail&, const resource_detail&)
      = default;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& h,
      const resource_detail& r) {
        h.update(r.name);
        h.update(r.type);
    }
};

static inline actor result_to_actor(const security::auth_result& result) {
    user user{
      .name = result.principal.name(),
      .type_id = result.is_superuser ? user::type::admin : user::type::user,
    };

    policy policy;
    policy.name = "aclAuthorization";

    if (result.authorization_disabled) {
        policy.desc = "authorization disabled";
    } else if (result.is_superuser) {
        policy.desc = "superuser";
    } else if (result.empty_matches) {
        policy.desc = "no matches";
    } else if (result.acl || result.resource_pattern) {
        ss::sstring desc;
        if (result.acl) {
            desc += fmt::format("acl: {}", *result.acl);
        }
        if (result.resource_pattern) {
            if (!desc.empty()) {
                desc += ", ";
            }
            desc += fmt::format("resource: {}", *result.resource_pattern);
        }

        policy.desc = std::move(desc);
    }

    std::vector<authorization_result> auths;
    auths.reserve(1);
    auths.emplace_back(authorization_result{
      .decision = result.authorized ? "authorized" : "denied",
      .policy = std::move(policy)});

    return {
      .authorizations = std::move(auths),
      .user = std::move(user),
    };
}
} // namespace security::audit

namespace json {
inline void
rjson_serialize(Writer<StringBuffer>& w, const security::audit::api& api) {
    w.StartObject();
    w.Key("operation");
    rjson_serialize(w, api.operation);
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::product& product) {
    w.StartObject();
    w.Key("name");
    rjson_serialize(w, product.name);
    w.Key("vendor_name");
    rjson_serialize(w, product.vendor_name);
    w.Key("version");
    rjson_serialize(w, product.version);
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::metadata& metadata) {
    w.StartObject();
    w.Key("version");
    rjson_serialize(w, metadata.version);
    w.Key("product");
    rjson_serialize(w, metadata.product);
    w.EndObject();
    ;
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::network_endpoint& endpoint) {
    w.StartObject();
    if (!endpoint.intermediate_ips.empty()) {
        w.Key("intermediate_ips");
        rjson_serialize(w, endpoint.intermediate_ips);
    }
    w.Key("ip");
    rjson_serialize(w, endpoint.ip);
    if (!endpoint.name.empty()) {
        w.Key("name");
        rjson_serialize(w, endpoint.name);
    }
    w.Key("port");
    rjson_serialize(w, endpoint.port);
    if (!endpoint.uid.empty()) {
        w.Key("uid");
        rjson_serialize(w, endpoint.uid);
    }
    w.EndObject();
}

inline void
rjson_serialize(Writer<StringBuffer>& w, const security::audit::policy& p) {
    w.StartObject();
    w.Key("name");
    rjson_serialize(w, p.name);
    w.Key("desc");
    rjson_serialize(w, p.desc);
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::authorization_result& authz) {
    w.StartObject();
    w.Key("decision");
    rjson_serialize(w, authz.decision);
    w.Key("policy");
    rjson_serialize(w, authz.policy);
    w.EndObject();
}

inline void
rjson_serialize(Writer<StringBuffer>& w, const security::audit::user& user) {
    w.StartObject();
    if (!user.credential_uid.empty()) {
        w.Key("credential_uid");
        rjson_serialize(w, user.credential_uid);
    }
    if (!user.domain.empty()) {
        w.Key("domain");
        rjson_serialize(w, user.domain);
    }
    w.Key("type_id");
    rjson_serialize(w, user.type_id);
    w.Key("name");
    rjson_serialize(w, user.name);
    w.EndObject();
}

inline void
rjson_serialize(Writer<StringBuffer>& w, const security::audit::actor& actor) {
    w.StartObject();
    w.Key("authorizations");
    rjson_serialize(w, actor.authorizations);
    w.Key("user");
    rjson_serialize(w, actor.user);
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::resource_detail& resource) {
    w.StartObject();
    w.Key("name");
    rjson_serialize(w, resource.name);
    w.Key("type");
    rjson_serialize(w, resource.type);
    w.EndObject();
}

} // namespace json
