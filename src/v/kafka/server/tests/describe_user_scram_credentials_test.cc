// Copyright 2025 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "cluster/security_frontend.h"
#include "kafka/protocol/describe_user_scram_credentials.h"
#include "kafka/protocol/types.h"
#include "kafka/server/handlers/details/security.h"
#include "model/timeout_clock.h"
#include "redpanda/tests/fixture.h"
#include "security/acl.h"
#include "security/scram_algorithm.h"
#include "security/scram_credential.h"
#include "security/types.h"

#include <seastar/core/sstring.hh>

#include <absl/algorithm/container.h>

class describe_user_scram_credentials_fixture : public redpanda_thread_fixture {
protected:
    static constexpr auto user_name_256 = "test_user_256";
    static constexpr auto user_name_512 = "test_user_512";
    static constexpr auto password_256 = "password256";
    static constexpr auto password_512 = "password512";
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

    void validate_user_response_two_users(
      const kafka::describe_user_scram_credentials_response& resp) {
        BOOST_REQUIRE(!resp.data.errored());
        BOOST_REQUIRE_EQUAL(resp.data.results.size(), 2);
        bool saw_sha256 = false, saw_sha512 = false;

        for (const auto& result : resp.data.results) {
            BOOST_REQUIRE_EQUAL(result.credential_infos.size(), 1);
            if (result.user == user_name_256) {
                BOOST_REQUIRE(!saw_sha256);
                BOOST_CHECK_EQUAL(
                  result.credential_infos[0].mechanism,
                  kafka::scram_mechanism::scram_sha_256);
                BOOST_CHECK_EQUAL(
                  result.credential_infos[0].iterations,
                  security::scram_sha256::min_iterations);
                saw_sha256 = true;
            } else if (result.user == user_name_512) {
                BOOST_REQUIRE(!saw_sha512);
                BOOST_CHECK_EQUAL(
                  result.credential_infos[0].mechanism,
                  kafka::scram_mechanism::scram_sha_512);
                BOOST_CHECK_EQUAL(
                  result.credential_infos[0].iterations,
                  security::scram_sha512::min_iterations);
                saw_sha512 = true;
            } else {
                BOOST_FAIL(
                  fmt::format("Unexpected user name: {}", result.user));
            }
        }

        BOOST_REQUIRE(saw_sha256 && saw_sha512);
    }
};

FIXTURE_TEST(
  describe_user_scram_credentials_no_auth,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    auto creds_256 = security::scram_sha256::make_credentials(
      password_256, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    auto creds_512 = security::scram_sha512::make_credentials(
      password_512, security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    kafka::describe_user_scram_credentials_request req;

    auto client = make_kafka_client().get();
    client.connect().get();

    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    validate_user_response_two_users(resp);
}

FIXTURE_TEST(
  describe_user_scram_credentials_auth,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    auto creds_256 = security::scram_sha256::make_credentials(
      password_256, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    auto creds_512 = security::scram_sha512::make_credentials(
      password_512, security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    enable_sasl();

    auto disable_sasl_defer = ss::defer([this] { disable_sasl(); });

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
    authn_kafka_client(client, user_name_256, password_256);

    kafka::describe_user_scram_credentials_request req;

    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    validate_user_response_two_users(resp);
}

FIXTURE_TEST(
  describe_user_scram_credentials_not_authz,
  describe_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    auto creds_256 = security::scram_sha256::make_credentials(
      password_256, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    auto creds_512 = security::scram_sha512::make_credentials(
      password_512, security::scram_sha512::min_iterations);
    create_user(user_name_512, creds_512);

    enable_sasl();

    auto disable_sasl_defer = ss::defer([this] { disable_sasl(); });

    auto client = make_kafka_client().get();
    client.connect().get();
    authn_kafka_client(client, user_name_256, password_256);

    kafka::describe_user_scram_credentials_request req;
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_REQUIRE(resp.data.errored());
    BOOST_REQUIRE_EQUAL(
      resp.data.error_code, kafka::error_code::cluster_authorization_failed);
    BOOST_REQUIRE(resp.data.results.empty());
}
