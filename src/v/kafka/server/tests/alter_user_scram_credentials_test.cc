// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "kafka/protocol/alter_user_scram_credentials.h"
#include "redpanda/tests/fixture.h"
#include "security/scram_algorithm.h"

class alter_user_scram_credentials_fixture : public redpanda_thread_fixture {};

FIXTURE_TEST(
  alter_user_scram_credentials_no_auth, alter_user_scram_credentials_fixture) {
    wait_for_controller_leadership().get();
    ss::sstring user_name_256 = "test_user_256";
    ss::sstring password = "password";
    auto [creds, salted_password]
      = security::scram_sha256::make_credentials_and_password(
        password, security::scram_sha256::min_iterations);
    auto client = make_kafka_client().get();
    client.connect().get();
    kafka::alter_user_scram_credentials_request req;
    req.data.upsertions.emplace_back(kafka::scram_credential_upsertion{
      .name = kafka::scram_user_name(user_name_256),
      .mechanism = kafka::scram_mechanism::scram_sha_256,
      .iterations = security::scram_sha256::min_iterations,
      .salt = creds.salt(),
      .salted_password = salted_password});
    auto resp = client.dispatch(std::move(req), kafka::api_version(0)).get();
    BOOST_REQUIRE(!resp.data.errored());
    BOOST_REQUIRE_EQUAL(resp.data.results.size(), 1);
    BOOST_CHECK_EQUAL(resp.data.results[0].user, user_name_256);
    BOOST_CHECK_EQUAL(resp.data.results[0].error_code, kafka::error_code::none);
}
