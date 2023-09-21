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
#include "utils/request_auth.h"
#include "version.h"

#include <seastar/http/httpd.hh>

#include <boost/algorithm/string.hpp>

#pragma once

namespace security::audit {

static constexpr std::string_view ocsf_api_version = "1.0.0";
static constexpr std::string_view vendor_name = "Redpanda Data, Inc.";

using timestamp_t = named_type<long, struct timestamp_t_type>;
using type_uid = named_type<long, struct type_uid_type>;

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

struct product {
    ss::sstring name;
    ss::sstring vendor_name;
    ss::sstring version;

    friend bool operator==(const product&, const product&) = default;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& h,
      const product& p) {
        h.update(p.name);
        h.update(p.vendor_name);
        h.update(p.version);
    }
};

static const product redpanda_product = {
  .name = "Redpanda",
  .vendor_name = ss::sstring{vendor_name},
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
    ss::sstring svc_name;
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
    std::optional<policy> policy;

    friend bool
    operator==(const authorization_result&, const authorization_result&)
      = default;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const authorization_result& result) {
        hash.update(result.decision);
        if (result.policy) {
            hash.update(result.policy);
        }
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

struct authorization_metadata {
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
      const authorization_metadata& u) {
        h.update(u.acl_authorization.host);
        h.update(u.acl_authorization.op);
        h.update(u.acl_authorization.permission_type);
        h.update(u.acl_authorization.principal);
        h.update(u.resource.name);
        h.update(u.resource.pattern);
        h.update(u.resource.type);
    }
};

struct api_activity_unmapped {
    ss::shard_id shard_id;
    std::optional<authorization_metadata> authorization_metadata;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& h,
      const api_activity_unmapped& u) {
        h.update(u.shard_id);
        if (u.authorization_metadata) {
            h.update(u.authorization_metadata.value());
        }
    }
};

struct http_header {
    ss::sstring name;
    ss::sstring value;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& hash,
      const http_header& h) {
        hash.update(h.name);
        hash.update(h.value);
    }
};

struct uniform_resource_locator {
    ss::sstring hostname;
    ss::sstring path;
    std::uint16_t port;
    ss::sstring scheme;
    ss::sstring url_string;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& h,
      const uniform_resource_locator& url) {
        h.update(url.hostname);
        h.update(url.path);
        h.update(url.port);
        h.update(url.scheme);
        h.update(url.url_string);
    }
};

struct http_request {
    fragmented_vector<http_header> http_headers;
    ss::sstring http_method;
    uniform_resource_locator url;
    ss::sstring user_agent;
    ss::sstring version;

    friend void tag_invoke(
      tag_t<incremental_xxhash64_tag>,
      incremental_xxhash64& h,
      const http_request& r) {
        for (const auto& hdr : r.http_headers) {
            h.update(hdr);
        }
        h.update(r.http_method);
        h.update(r.url);
        h.update(r.user_agent);
        h.update(r.version);
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

static inline actor
auth_result_to_actor(const request_auth_result& r, bool authorized) {
    user user{
      .name = r.get_username(),
      .type_id = r.is_superuser() ? user::type::admin : user::type::user,
    };

    std::vector<authorization_result> auths;
    auths.reserve(1);
    auths.emplace_back(
      authorization_result{.decision = authorized ? "authorized" : "denied"});

    return {.authorizations = std::move(auths), .user = std::move(user)};
}

static inline fragmented_vector<http_header>
create_headers(ss::httpd::const_req req) {
    fragmented_vector<http_header> rv;

    std::transform(
      req._headers.begin(),
      req._headers.end(),
      std::back_inserter(rv),
      [](const auto& h) -> http_header {
          return {
            .name = h.first,
            .value = boost::iequals(h.first, "authorization") ? "******"
                                                              : h.second};
      });

    return rv;
}

static inline uniform_resource_locator req_to_url(ss::httpd::const_req req) {
    return {
      .hostname = req.get_header("Host"),
      .path = req.format_url(),
      .scheme = req.get_protocol_name(),
      .url_string = req.get_url()};
}

static inline http_request create_http_request(ss::httpd::const_req req) {
    return {
      .http_headers = create_headers(req),
      .http_method = req._method,
      .url = req_to_url(req),
      .user_agent = req.get_header("user-agent"),
      .version = req._version};
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
    if (!endpoint.svc_name.empty()) {
        w.Key("svc_name");
        rjson_serialize(w, endpoint.svc_name);
    }
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
    if (authz.policy) {
        w.Key("policy");
        rjson_serialize(w, authz.policy);
    }

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

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::authorization_metadata& m) {
    w.StartObject();
    w.Key("acl_authorization");
    w.StartObject();
    w.Key("host");
    ::json::rjson_serialize(w, m.acl_authorization.host);
    w.Key("op");
    ::json::rjson_serialize(w, m.acl_authorization.op);
    w.Key("permission_type");
    ::json::rjson_serialize(w, m.acl_authorization.permission_type);
    w.Key("principal");
    ::json::rjson_serialize(w, m.acl_authorization.principal);
    w.EndObject();
    w.Key("resource");
    w.StartObject();
    w.Key("name");
    ::json::rjson_serialize(w, m.resource.name);
    w.Key("pattern");
    ::json::rjson_serialize(w, m.resource.pattern);
    w.Key("type");
    ::json::rjson_serialize(w, m.resource.type);
    w.EndObject();
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::api_activity_unmapped& u) {
    w.StartObject();
    w.Key("shard_id");
    ::json::rjson_serialize(w, u.shard_id);
    if (u.authorization_metadata) {
        w.Key("authorization_metadata");
        ::json::rjson_serialize(w, u.authorization_metadata.value());
    }
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::http_header& h) {
    w.StartObject();
    w.Key("name");
    json::rjson_serialize(w, h.name);
    w.Key("value");
    json::rjson_serialize(w, h.value);
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w,
  const security::audit::uniform_resource_locator& url) {
    w.StartObject();
    w.Key("hostname");
    rjson_serialize(w, url.hostname);
    w.Key("path");
    rjson_serialize(w, url.path);
    w.Key("port");
    rjson_serialize(w, url.port);
    w.Key("scheme");
    rjson_serialize(w, url.scheme);
    w.Key("url_string");
    rjson_serialize(w, url.url_string);
    w.EndObject();
}

inline void rjson_serialize(
  Writer<StringBuffer>& w, const security::audit::http_request& r) {
    w.StartObject();
    w.Key("http_headers");
    w.StartArray();
    for (const auto& h : r.http_headers) {
        rjson_serialize(w, h);
    }
    w.EndArray();
    w.Key("http_method");
    rjson_serialize(w, r.http_method);
    w.Key("url");
    rjson_serialize(w, r.url);
    w.Key("user_agent");
    rjson_serialize(w, r.user_agent);
    w.Key("version");
    rjson_serialize(w, r.version);
    w.EndObject();
}

} // namespace json

namespace std {

template<>
struct hash<security::audit::authorization_metadata> {
    size_t operator()(const security::audit::authorization_metadata& m) {
        size_t h = 0;
        boost::hash_combine(
          h, std::hash<ss::sstring>()(m.acl_authorization.host));
        boost::hash_combine(
          h, std::hash<ss::sstring>()(m.acl_authorization.op));
        boost::hash_combine(
          h, std::hash<ss::sstring>()(m.acl_authorization.permission_type));
        boost::hash_combine(
          h, std::hash<ss::sstring>()(m.acl_authorization.principal));
        boost::hash_combine(h, std::hash<ss::sstring>()(m.resource.name));
        boost::hash_combine(h, std::hash<ss::sstring>()(m.resource.pattern));
        boost::hash_combine(h, std::hash<ss::sstring>()(m.resource.type));

        return h;
    }
};

template<>
struct hash<security::audit::api_activity_unmapped> {
    size_t operator()(const security::audit::api_activity_unmapped& u) {
        size_t h = 0;
        boost::hash_combine(h, std::hash<ss::shard_id>()(u.shard_id));
        if (u.authorization_metadata) {
            boost::hash_combine(
              h,
              std::hash<security::audit::authorization_metadata>()(
                u.authorization_metadata.value()));
        }

        return h;
    }
};
template<>
struct hash<security::audit::resource_detail> {
    size_t operator()(const security::audit::resource_detail& r) {
        size_t h = 0;
        boost::hash_combine(h, std::hash<ss::sstring>()(r.name));
        boost::hash_combine(h, std::hash<ss::sstring>()(r.type));
        return h;
    }
};

template<>
struct hash<security::audit::user> {
    size_t operator()(const security::audit::user& u) {
        size_t h = 0;
        boost::hash_combine(h, std::hash<ss::sstring>()(u.credential_uid));
        boost::hash_combine(h, std::hash<ss::sstring>()(u.domain));
        boost::hash_combine(h, std::hash<ss::sstring>()(u.name));
        boost::hash_combine(h, std::hash<int>()(int(u.type_id)));
        return h;
    }
};

template<>
struct hash<security::audit::policy> {
    size_t operator()(const security::audit::policy& p) {
        size_t h = 0;

        boost::hash_combine(h, std::hash<ss::sstring>()(p.name));
        boost::hash_combine(h, std::hash<ss::sstring>()(p.desc));

        return h;
    }
};

template<>
struct hash<security::audit::authorization_result> {
    size_t operator()(const security::audit::authorization_result& r) {
        size_t h = 0;
        boost::hash_combine(h, std::hash<ss::sstring>()(r.decision));
        if (r.policy) {
            boost::hash_combine(
              h, std::hash<security::audit::policy>()(r.policy.value()));
        }

        return h;
    }
};

template<>
struct hash<security::audit::actor> {
    size_t operator()(const security::audit::actor& a) {
        size_t h = 0;

        for (const auto& authzs : a.authorizations) {
            boost::hash_combine(
              h, std::hash<security::audit::authorization_result>()(authzs));
        }

        boost::hash_combine(h, std::hash<security::audit::user>()(a.user));

        return h;
    }
};

template<>
struct hash<security::audit::api> {
    size_t operator()(const security::audit::api& a) {
        size_t h = 0;

        boost::hash_combine(h, std::hash<ss::sstring>()(a.operation));

        return h;
    }
};

template<>
struct hash<security::audit::product> {
    size_t operator()(const security::audit::product& p) {
        size_t h = 0;

        boost::hash_combine(h, std::hash<ss::sstring>()(p.name));
        boost::hash_combine(h, std::hash<ss::sstring>()(p.version));
        boost::hash_combine(h, std::hash<ss::sstring>()(p.vendor_name));

        return h;
    }
};

template<>
struct hash<security::audit::http_header> {
    size_t operator()(const security::audit::http_header& header) {
        size_t h;

        boost::hash_combine(h, std::hash<ss::sstring>()(header.name));
        boost::hash_combine(h, std::hash<ss::sstring>()(header.value));

        return h;
    }
};

template<>
struct hash<security::audit::uniform_resource_locator> {
    size_t operator()(const security::audit::uniform_resource_locator& url) {
        size_t h;

        boost::hash_combine(h, std::hash<ss::sstring>()(url.hostname));
        boost::hash_combine(h, std::hash<ss::sstring>()(url.path));
        boost::hash_combine(h, std::hash<ss::sstring>()(url.scheme));
        boost::hash_combine(h, std::hash<ss::sstring>()(url.url_string));
        boost::hash_combine(h, std::hash<std::uint16_t>()(url.port));

        return h;
    }
};

template<>
struct hash<security::audit::http_request> {
    size_t operator()(const security::audit::http_request& r) {
        size_t h;

        for (const auto& hdr : r.http_headers) {
            boost::hash_combine(
              h, std::hash<security::audit::http_header>()(hdr));
        }
        boost::hash_combine(h, std::hash<ss::sstring>()(r.http_method));
        boost::hash_combine(
          h, std::hash<security::audit::uniform_resource_locator>()(r.url));
        boost::hash_combine(h, std::hash<ss::sstring>()(r.user_agent));
        boost::hash_combine(h, std::hash<ss::sstring>()(r.version));

        return h;
    }
};
} // namespace std
