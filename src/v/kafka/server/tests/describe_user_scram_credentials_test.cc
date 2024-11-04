// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "cluster/security_frontend.h"
#include "kafka/protocol/describe_user_scram_credentials.h"
#include "kafka/protocol/errors.h"
#include "kafka/protocol/types.h"
#include "kafka/server/handlers/details/security.h"
#include "redpanda/tests/fixture.h"
#include "security/scram_algorithm.h"
#include "security/scram_credential.h"

class describe_user_scram_credentials_fixture : public redpanda_thread_fixture {
protected:
    void create_user(
      std::string_view username, security::scram_credential credentials) {
        app.controller->get_security_frontend()
          .local()
          .create_user(
            security::credential_user(username),
            std::move(credentials),
            model::timeout_clock::now() + 5s)
          .get();
    }
};

FIXTURE_TEST(
  describe_user_scram_credentials_no_auth,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    ss::sstring user_name_256 = "test_user_256";
    auto creds_256 = security::scram_sha256::make_credentials(
      "password", security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    ss::sstring user_name_512 = "test_user_512";
    auto creds_512 = security::scram_sha512::make_credentials(
      "password", security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    kafka::describe_user_scram_credentials_request req;

    auto client = make_kafka_client().get();
    client.connect().get();
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_REQUIRE(!resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 2);
    bool saw_sha256 = false, saw_sha512 = false;
    for (const auto& result : resp.data.results) {
        BOOST_REQUIRE_EQUAL(result.credential_infos.size(), 1);
        if (result.user == user_name_256) {
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].mechanism,
              kafka::scram_mechanism::scram_sha_256);
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].iterations,
              security::scram_sha256::min_iterations);
            saw_sha256 = true;
        } else if (result.user == user_name_512) {
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].mechanism,
              kafka::scram_mechanism::scram_sha_512);
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].iterations,
              security::scram_sha512::min_iterations);
            saw_sha512 = true;
        } else {
            BOOST_FAIL("Unexpected user in response");
        }
    }

    BOOST_REQUIRE(saw_sha256 && saw_sha512);
}

FIXTURE_TEST(
  describe_user_scram_credentials_authz,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    ss::sstring user_name_256 = "test_user_256";
    ss::sstring user_name_256_password = "password";
    auto creds_256 = security::scram_sha256::make_credentials(
      user_name_256_password, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    ss::sstring user_name_512 = "test_user_512";
    auto creds_512 = security::scram_sha512::make_credentials(
      "password", security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    enable_sasl();

    std::vector<security::acl_binding> cluster_bindings{security::acl_binding(
      security::resource_pattern(
        security::resource_type::cluster,
        security::default_cluster_name,
        security::pattern_type::literal),
      security::acl_entry(
        kafka::details::to_acl_principal(
          ssx::sformat("User:{}", user_name_256)),
        security::acl_host::wildcard_host(),
        security::acl_operation::describe,
        security::acl_permission::allow))};

    auto acl_result = app.controller->get_security_frontend()
                        .local()
                        .create_acls(std::move(cluster_bindings), 1s)
                        .get();

    const auto errors_in_acl_results =
      [](const std::vector<cluster::errc>& errs) {
          return absl::c_any_of(errs, [](const cluster::errc& e) {
              return e != cluster::errc::success;
          });
      };

    BOOST_REQUIRE(!errors_in_acl_results(acl_result));

    auto client = make_kafka_client().get();
    client.connect().get();
    authn_kafka_client(client, user_name_256, user_name_256_password);

    kafka::describe_user_scram_credentials_request req;
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_REQUIRE(!resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 2);
    bool saw_sha256 = false, saw_sha512 = false;
    for (const auto& result : resp.data.results) {
        BOOST_REQUIRE_EQUAL(result.credential_infos.size(), 1);
        if (result.user == user_name_256) {
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].mechanism,
              kafka::scram_mechanism::scram_sha_256);
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].iterations,
              security::scram_sha256::min_iterations);
            saw_sha256 = true;
        } else if (result.user == user_name_512) {
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].mechanism,
              kafka::scram_mechanism::scram_sha_512);
            BOOST_CHECK_EQUAL(
              result.credential_infos[0].iterations,
              security::scram_sha512::min_iterations);
            saw_sha512 = true;
        } else {
            BOOST_FAIL("Unexpected user in response");
        }
    }

    BOOST_REQUIRE(saw_sha256 && saw_sha512);
}

FIXTURE_TEST(
  describe_user_scram_credentials_not_authz,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    ss::sstring user_name_256 = "test_user_256";
    ss::sstring user_name_256_password = "password";
    auto creds_256 = security::scram_sha256::make_credentials(
      user_name_256_password, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    ss::sstring user_name_512 = "test_user_512";
    auto creds_512 = security::scram_sha512::make_credentials(
      "password", security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    enable_sasl();

    std::vector<security::acl_binding> cluster_bindings{security::acl_binding(
      security::resource_pattern(
        security::resource_type::cluster,
        security::default_cluster_name,
        security::pattern_type::literal),
      security::acl_entry(
        kafka::details::to_acl_principal(
          ssx::sformat("User:{}", user_name_512)),
        security::acl_host::wildcard_host(),
        security::acl_operation::describe,
        security::acl_permission::allow))};

    auto acl_result = app.controller->get_security_frontend()
                        .local()
                        .create_acls(std::move(cluster_bindings), 1s)
                        .get();

    const auto errors_in_acl_results =
      [](const std::vector<cluster::errc>& errs) {
          return absl::c_any_of(errs, [](const cluster::errc& e) {
              return e != cluster::errc::success;
          });
      };

    BOOST_REQUIRE(!errors_in_acl_results(acl_result));
    auto client = make_kafka_client().get();
    client.connect().get();
    authn_kafka_client(client, user_name_256, user_name_256_password);

    kafka::describe_user_scram_credentials_request req;
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_REQUIRE(resp.data.errored());
    BOOST_REQUIRE_EQUAL(
      resp.data.error_code, kafka::error_code::cluster_authorization_failed);
    BOOST_REQUIRE(resp.data.results.empty());
}

FIXTURE_TEST(
  describe_user_scram_credentials_no_user,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    auto client = make_kafka_client().get();
    client.connect().get();
    kafka::describe_user_scram_credentials_request req;
    req.data.users.emplace(chunked_vector<kafka::user_name>{
      {.name = kafka::scram_user_name("test_user")}});
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_CHECK(resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 1);
    BOOST_CHECK_EQUAL(resp.data.results[0].user, "test_user");
    BOOST_CHECK_EQUAL(
      resp.data.results[0].error_code, kafka::error_code::resource_not_found);
}

FIXTURE_TEST(
  describe_user_scram_credentials_multi_no_user,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    auto client = make_kafka_client().get();
    client.connect().get();
    kafka::describe_user_scram_credentials_request req;
    req.data.users.emplace(chunked_vector<kafka::user_name>{
      {.name = kafka::scram_user_name("test_user")},
      {.name = kafka::scram_user_name("test_user")}});
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_CHECK(resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 2);
    for (const auto& r : resp.data.results) {
        BOOST_CHECK_EQUAL(r.user, "test_user");
        BOOST_CHECK_EQUAL(r.error_code, kafka::error_code::resource_not_found);
    }
}

FIXTURE_TEST(
  describe_user_scram_credentials_multi_user,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    ss::sstring user_name_256 = "test_user_256";
    ss::sstring user_name_256_password = "password";
    auto creds_256 = security::scram_sha256::make_credentials(
      user_name_256_password, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    ss::sstring user_name_512 = "test_user_512";
    auto creds_512 = security::scram_sha512::make_credentials(
      "password", security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    kafka::describe_user_scram_credentials_request req;

    req.data.users.emplace(chunked_vector<kafka::user_name>{
      {.name = kafka::scram_user_name(user_name_256)},
      {.name = kafka::scram_user_name(user_name_256)}});

    auto client = make_kafka_client().get();
    client.connect().get();
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_CHECK(resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 2);

    for (const auto& r : resp.data.results) {
        BOOST_CHECK_EQUAL(r.user, user_name_256);
        BOOST_CHECK_EQUAL(r.error_code, kafka::error_code::duplicate_resource);
    }
}

FIXTURE_TEST(
  describe_user_scram_credentials_mix,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    ss::sstring user_name_256 = "test_user_256";
    ss::sstring user_name_256_password = "password";
    auto creds_256 = security::scram_sha256::make_credentials(
      user_name_256_password, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    ss::sstring user_name_512 = "test_user_512";
    auto creds_512 = security::scram_sha512::make_credentials(
      "password", security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    kafka::describe_user_scram_credentials_request req;

    req.data.users.emplace(chunked_vector<kafka::user_name>{
      {.name = kafka::scram_user_name(user_name_256)},
      {.name = kafka::scram_user_name(user_name_256)},
      {.name = kafka::scram_user_name("test_user")},
      {.name = kafka::scram_user_name(user_name_512)}});

    auto client = make_kafka_client().get();
    client.connect().get();
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_CHECK(resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 4);

    bool seen_512 = false, seen_test_user = false;
    unsigned int seen_256_count = 0;

    for (const auto& r : resp.data.results) {
        if (r.user == user_name_256) {
            seen_256_count++;
            BOOST_CHECK_EQUAL(
              r.error_code, kafka::error_code::duplicate_resource);
        } else if (r.user == user_name_512) {
            seen_512 = true;
            BOOST_REQUIRE_EQUAL(r.error_code, kafka::error_code::none);
            BOOST_REQUIRE_EQUAL(r.credential_infos.size(), 1);
            BOOST_CHECK_EQUAL(
              r.credential_infos[0].mechanism,
              kafka::scram_mechanism::scram_sha_512);
            BOOST_CHECK_EQUAL(
              r.credential_infos[0].iterations,
              security::scram_sha512::min_iterations);
        } else if (r.user == "test_user") {
            seen_test_user = true;
            BOOST_CHECK_EQUAL(
              r.error_code, kafka::error_code::resource_not_found);
        } else {
            BOOST_FAIL("Unexpected user in response");
        }
    }

    BOOST_REQUIRE(seen_512 && seen_test_user && seen_256_count == 2);
}
