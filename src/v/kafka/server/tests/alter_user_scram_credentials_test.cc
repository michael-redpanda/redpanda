// Copyright 2025 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "cluster/security_frontend.h"
#include "kafka/protocol/alter_user_scram_credentials.h"
#include "kafka/protocol/types.h"
#include "redpanda/tests/fixture.h"
#include "security/scram_algorithm.h"
#include "security/types.h"

class alter_user_scram_credentials_fixture : public redpanda_thread_fixture {
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
};

FIXTURE_TEST(
  alter_user_scram_credentials_not_authz,
  alter_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();

    auto creds_256 = security::scram_sha256::make_credentials(
      password_256, security::scram_sha256::min_iterations);
    create_user(user_name_256, creds_256);

    auto [creds_512, salted_password_512]
      = security::scram_sha512::make_credentials_and_return_password(
        password_512, security::scram_sha512::min_iterations);

    enable_sasl();

    auto disable_sasl_defer = ss::defer([this] { disable_sasl(); });

    auto client = make_kafka_client().get();
    client.connect().get();
    authn_kafka_client(client, user_name_256, password_256);

    kafka::alter_user_scram_credentials_request req;
    req.data.upsertions.emplace_back(kafka::scram_credential_upsertion{
      .name = kafka::scram_user_name{user_name_512},
      .mechanism = kafka::scram_mechanism::scram_sha_512,
      .iterations = security::scram_sha512::min_iterations,
      .salt = creds_512.salt(),
      .salted_password = salted_password_512,
    });

    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_REQUIRE(resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 1);
    BOOST_CHECK_EQUAL(resp.data.results[0].user, user_name_512);
    BOOST_CHECK_EQUAL(
      resp.data.results[0].error_code,
      kafka::error_code::cluster_authorization_failed);
}
