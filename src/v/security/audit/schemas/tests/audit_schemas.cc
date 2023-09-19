// Copyright 2023 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "json/reader.h"
#include "json/stream.h"
#include "json/stringbuffer.h"
#include "seastarx.h"
#include "security/acl.h"
#include "security/audit/schemas/application_activity.h"
#include "security/audit/schemas/iam.h"
#include "security/audit/schemas/schemas.h"
#include "security/audit/schemas/types.h"
#include "security/authorizer.h"
#include "utils/fragmented_vector.h"
#include "version.h"

#include <seastar/net/socket_defs.hh>
#include <seastar/testing/thread_test_case.hh>

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

#include <optional>

namespace sa = security::audit;

inline ss::sstring minify(std::string_view json) {
    ::json::Reader r;
    ::json::StringStream in(json.data());
    ::json::StringBuffer out;
    ::json::Writer<::json::StringBuffer> w{out};
    r.Parse(in, w);
    return ss::sstring(out.GetString(), out.GetSize());
}

static const sa::network_endpoint dst_endpoint{
  .intermediate_ips = {},
  .ip = "1.1.1.1",
  .name = "",
  .port = 9021,
  .uid = "cluster1",
};

static const ss::sstring dst_endpoint_json{
  R"(
    "dst_endpoint": {
        "ip": "1.1.1.1",
        "port": 9021,
        "uid": "cluster1"
    }
    )"};

static const ss::sstring metadata_object{
  R"(
    "metadata": {
        "version": "1.0.0",
        "product": {
            "name": "Redpanda",
            "vendor_name": "Redpanda Data, Inc",
            "version": ")"
  + ss::sstring{redpanda_git_version()} + R"("
        }
    }
    )"};

static const sa::network_endpoint src_endpoint{
  .intermediate_ips = {"3.3.3.3"},
  .ip = "2.2.2.2",
  .name = "rpk",
  .port = 11111,
  .uid = "",
};

static const ss::sstring src_endpoint_json{
  R"(
    "src_endpoint": {
        "intermediate_ips": ["3.3.3.3"],
        "ip": "2.2.2.2",
        "name": "rpk",
        "port": 11111
    }
    )"};

SEASTAR_THREAD_TEST_CASE(test_application_activity) {
    fragmented_vector<sa::resource_detail> resources;
    resources.emplace_back(
      sa::resource_detail{.name = "topic1", .type = "topic"});
    struct sa::api_activity_unmapped unmapped {};
    sa::api_activity api_activity{
      sa::api_activity::activity_id::create,
      sa::actor{
        .authorizations = {sa::authorization_result{
          .decision = "denied",
          .policy = {.name = "aclAuthorization", .desc = "{{}}"}}},
        .user = {.name = "User:mboquard", .type_id = sa::user::type::user}},
      sa::api{.operation = "create_topic"},
      dst_endpoint,
      std::move(resources),
      sa::api_activity::severity::informational,
      src_endpoint,
      sa::api_activity::status_id::failure,
      sa::timestamp_t{12345},
      unmapped};

    ::json::StringBuffer str_buf;
    ::json::Writer<::json::StringBuffer> wrt(str_buf);

    sa::rjson_serialize(wrt, api_activity);

    ss::sstring result{str_buf.GetString(), str_buf.GetSize()};

    const ss::sstring expected = {
      R"(
{
    "activity_id": 1,
    "actor": {
        "authorizations": [
            {
                "decision": "denied",
                "policy": {
                    "name": "aclAuthorization",
                    "desc": "{{}}"
                }
            }
        ],
        "user": {
            "type_id": 1,
            "name": "User:mboquard"
        }
    },
    "api": {
        "operation": "create_topic"
    },
    "category_uid": 6,
    "class_uid": 6003,
    )" + dst_endpoint_json
      + R"(,)" + metadata_object + R"(, 
      "resources": [
        {
            "name": "topic1",
            "type": "topic"
        }
      ],
      "severity_id": 1,)"
      + src_endpoint_json + R"(,
    "status_id": 2,
    "time": 12345,
    "type_uid": 600301,
"unmapped": {
"acl_authorization": {
"host": "",
"op": "",
"permission_type": "",
"principal": ""
},
"resource": {
"name": "",
"pattern": "",
"type": ""
}
}
})"};
    BOOST_REQUIRE_EQUAL(minify(expected), result);
}

SEASTAR_THREAD_TEST_CASE(test_authentication_kerberos) {
    sa::authentication authz{
      sa::authentication::activity_id::logon,
      sa::authentication::auth_protocol_id::kerberos,
      dst_endpoint,
      false,
      false,
      sa::authentication::severity::informational,
      src_endpoint,
      sa::authentication::status_id::success,
      123456,
      sa::user{
        .credential_uid = "mboquard/host",
        .domain = "EXAMPLE.COM",
        .name = "mboquard",
        .type_id = sa::user::type::user,
      }};

    ::json::StringBuffer str_buf;
    ::json::Writer<::json::StringBuffer> wrt(str_buf);

    sa::rjson_serialize(wrt, authz);

    ss::sstring result{str_buf.GetString(), str_buf.GetSize()};

    ss::sstring expected = R"(
{
    "activity_id": 1,
    "auth_protocol_id": 2,
    "category_uid": 3,
    "class_uid": 3002,
    )" + dst_endpoint_json + R"(,
        "is_cleartext": false,
        )" + metadata_object
                           + R"(,
    "mfa": false,
    "severity_id": 1,)" + src_endpoint_json
                           + R"(,
        "status_id": 1,
        "time": 123456,
        "type_uid": 300201,
        "user": {
            "credential_uid": "mboquard/host",
            "domain": "EXAMPLE.COM",
            "type_id": 1,
            "name": "mboquard"
        }
}
    )";
    BOOST_REQUIRE_EQUAL(minify(expected), result);
}

SEASTAR_THREAD_TEST_CASE(test_authentication_sasl) {
    sa::authentication authz{
      sa::authentication::activity_id::logon,
      ss::sstring{"SASL/SCRAM"},
      dst_endpoint,
      false,
      false,
      sa::authentication::severity::informational,
      src_endpoint,
      sa::authentication::status_id::success,
      123456,
      sa::user{
        .credential_uid = "",
        .domain = "",
        .name = "mboquard",
        .type_id = sa::user::type::user,
      }};

    ::json::StringBuffer str_buf;
    ::json::Writer<::json::StringBuffer> wrt(str_buf);

    sa::rjson_serialize(wrt, authz);

    ss::sstring result{str_buf.GetString(), str_buf.GetSize()};

    ss::sstring expected = R"(
{
    "activity_id": 1,
    "auth_protocol": "SASL/SCRAM",
    "auth_protocol_id": 99,
    "category_uid": 3,
    "class_uid": 3002,
    )" + dst_endpoint_json + R"(,
        "is_cleartext": false,
        )" + metadata_object
                           + R"(,
    "mfa": false,
    "severity_id": 1,)" + src_endpoint_json
                           + R"(,
        "status_id": 1,
        "time": 123456,
        "type_uid": 300201,
        "user": {
            "type_id": 1,
            "name": "mboquard"
        }
}
    )";
    BOOST_REQUIRE_EQUAL(minify(expected), result);
}

SEASTAR_THREAD_TEST_CASE(test_container) {
    struct underlying_list {};
    struct underlying_unordered_map {};

    using underlying_t = boost::multi_index_container<
      security::audit::audit_event,
      boost::multi_index::indexed_by<
        boost::multi_index::sequenced<boost::multi_index::tag<underlying_list>>,
        boost::multi_index::hashed_unique<
          boost::multi_index::tag<underlying_unordered_map>,
          boost::multi_index::member<
            security::audit::audit_event,
            size_t,
            &security::audit::audit_event::key>>>>;

    underlying_t item;

    auto& list = item.get<underlying_list>();
    auto& map = item.get<underlying_unordered_map>();

    auto result = security::auth_result::superuser_authorized(
      security::acl_principal{security::principal_type::user, "User:mboquard"},
      security::acl_wildcard_host);

    auto api_item = security::audit::create_api_activity(
      "test",
      security::acl_operation::create,
      result,
      ss::socket_address{},
      "test_svc",
      fragmented_vector<model::topic>{});

    list.emplace_back(security::audit::audit_event::create_audit_event(
      security::audit::create_api_activity(
        "test",
        security::acl_operation::create,
        result,
        ss::socket_address{},
        "test_svc",
        fragmented_vector<model::topic>{})));
    list.emplace_back(security::audit::audit_event::create_audit_event(
      security::audit::create_api_activity(
        "test",
        security::acl_operation::create,
        result,
        ss::socket_address{},
        "test_svc",
        fragmented_vector<model::topic>{})));

    BOOST_REQUIRE_EQUAL(item.size(), 1);

    auto find_res = map.find(api_item.key());
    BOOST_REQUIRE(find_res != map.end());
    find_res->increment(security::audit::timestamp_t{
      std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count()});
    BOOST_REQUIRE_EQUAL(find_res->count(), 2);

    auto ser = find_res->rjson_serialize();

    std::cout << ser << std::endl;
}
