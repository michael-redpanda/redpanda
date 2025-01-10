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

#include "security/acl.h"

namespace kafka {
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

    res.data.error_code = error_code::unsupported_version;
    res.data.error_message = ss::sstring{
      error_code_to_str(error_code::unsupported_version)};
    co_return co_await ctx.respond(std::move(res));
}
} // namespace kafka
