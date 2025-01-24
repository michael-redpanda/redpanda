/*
 * Copyright 2025 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#include "kafka/server/handlers/alter_user_scram_credentials.h"

#include "kafka/protocol/errors.h"
#include "security/acl.h"

namespace kafka {
namespace {

template<typename T>
kafka::alter_user_scram_credentials_result
generate_error(const T& item, kafka::error_code code, const ss::sstring& msg) {
    return {.user = item.name, .error_code = code, .error_message = msg};
}

template<typename Iter, typename ErrIter>
void populate_results_with_error(
  Iter begin,
  Iter end,
  ErrIter out_it,
  kafka::error_code ec,
  std::string_view msg) {
    std::transform(begin, end, out_it, [ec, &msg](const auto& item) {
        return generate_error(item, ec, ss::sstring{msg});
    });
};

void populate_results_with_error(
  const alter_user_scram_credentials_request_data& req,
  alter_user_scram_credentials_response_data& res,
  kafka::error_code ec,
  std::string_view err_msg) {
    res.results.reserve(req.upsertions.size() + req.deletions.size());
    populate_results_with_error(
      req.upsertions.cbegin(),
      req.upsertions.cend(),
      std::back_inserter(res.results),
      ec,
      err_msg);
    populate_results_with_error(
      req.deletions.cbegin(),
      req.deletions.cend(),
      std::back_inserter(res.results),
      ec,
      err_msg);
}
} // namespace
template<>
ss::future<response_ptr> alter_user_scram_credentials_handler::handle(
  request_context ctx, ss::smp_service_group) {
    alter_user_scram_credentials_request request;
    request.decode(ctx.reader(), ctx.header().version);
    log_request(ctx.header(), request);

    alter_user_scram_credentials_response res;

    if (unlikely(ctx.recovery_mode_enabled())) {
        populate_results_with_error(
          request.data,
          res.data,
          error_code::policy_violation,
          "Recovery mjode enabled");

        co_return co_await ctx.respond(std::move(res));
    }

    if (!ctx.authorized(
          security::acl_operation::alter, security::default_cluster_name)) {
        populate_results_with_error(
          request.data,
          res.data,
          error_code::cluster_authorization_failed,
          error_code_to_str(error_code::cluster_authorization_failed));

        co_return co_await ctx.respond(std::move(res));
    }

    if (!ctx.audit()) {
        res.data.results.reserve(
          request.data.upsertions.size() + request.data.deletions.size());
        populate_results_with_error(
          request.data.upsertions.cbegin(),
          request.data.upsertions.cend(),
          std::back_inserter(res.data.results),
          error_code::broker_not_available,
          "Broker not available - audit system failure");
        populate_results_with_error(
          request.data.deletions.cbegin(),
          request.data.deletions.cend(),
          std::back_inserter(res.data.results),
          error_code::broker_not_available,
          "Broker not available - audit system failure");

        co_return co_await ctx.respond(std::move(res));
    }

    co_return co_await ctx.respond(std::move(res));
}
} // namespace kafka
