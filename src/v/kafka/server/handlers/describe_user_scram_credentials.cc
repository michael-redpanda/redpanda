/*
 * Copyright 2024 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */
#include "kafka/server/handlers/describe_user_scram_credentials.h"

#include "kafka/protocol/types.h"
#include "security/acl.h"
#include "security/credential_store.h"
#include "security/scram_algorithm.h"
#include "security/scram_credential.h"

namespace kafka {

namespace {
scram_mechanism key_size_to_mechanism(size_t key_size) {
    switch (key_size) {
    case security::scram_sha256::key_size:
        return scram_mechanism::scram_sha_256;
    case security::scram_sha512::key_size:
        return scram_mechanism::scram_sha_512;
    default:
        return scram_mechanism::unknown;
    }
};

credential_info
scram_credential_to_credential_info(const security::scram_credential& c) {
    return {
      .mechanism = key_size_to_mechanism(c.stored_key().size()),
      .iterations = c.iterations(),
    };
};
} // namespace
template<>
ss::future<response_ptr> describe_user_scram_credentials_handler::handle(
  request_context ctx, ss::smp_service_group) {
    describe_user_scram_credentials_request request;
    request.decode(ctx.reader(), ctx.header().version);
    log_request(ctx.header(), request);

    describe_user_scram_credentials_response res;

    if (unlikely(ctx.recovery_mode_enabled())) {
        res.data.error_code = error_code::policy_violation;
        res.data.error_message = "Recovery mode enabled";
        co_return co_await ctx.respond(std::move(res));
    }

    if (!ctx.authorized(
          security::acl_operation::describe, security::default_cluster_name)) {
        res.data.error_code = error_code::cluster_authorization_failed;
        res.data.error_message = ss::sstring{
          error_code_to_str(error_code::cluster_authorization_failed)};
        co_return co_await ctx.respond(std::move(res));
    }

    if (!ctx.audit()) {
        res.data.error_code = error_code::broker_not_available;
        res.data.error_message = "Broker not available - audit system failure";
        co_return co_await ctx.respond(std::move(res));
    }

    const auto list_all_users = !request.data.users.has_value()
                                || request.data.users.value().empty();

    const auto add_user_to_results = [&res](
                                       const security::credential_user& user,
                                       const security::scram_credential& c) {
        res.data.results.emplace_back(describe_user_scram_credentials_result{
          .user = user,
          .credential_infos = {scram_credential_to_credential_info(c)}});
    };

    if (list_all_users) {
        const auto all_scram_users =
          [](const security::credential_store::container_type::value_type& t)
          -> bool {
            return ss::visit(
              t.second, [](const security::scram_credential&) { return true; });
        };
        for (const auto& c : ctx.credentials().range(all_scram_users)) {
            const auto& creds = std::get<security::scram_credential>(c.second);
            add_user_to_results(c.first, creds);
        }
    }

    co_return co_await ctx.respond(std::move(res));
}
} // namespace kafka
