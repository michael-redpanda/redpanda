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

#include <fmt/core.h>

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

template<typename T>
kafka::describe_user_scram_credentials_result
generate_error(const T& item, kafka::error_code code, std::string_view msg) {
    return {
      .user = item.name, .error_code = code, .error_message = ss::sstring{msg}};
}

template<typename Iter, typename ErrIter>
Iter validate_range_no_empty_users(Iter begin, Iter end, ErrIter out_it) {
    using type = typename Iter::value_type;
    auto valid_range_end = std::partition(
      begin, end, [](const type& item) { return !item.name().empty(); });

    std::transform(valid_range_end, end, out_it, [](const type& item) {
        return generate_error(
          item,
          kafka::error_code::resource_not_found,
          "User name cannot be empty");
    });

    return valid_range_end;
}

template<typename Iter, typename ErrIter>
Iter validate_range_duplicates(Iter begin, Iter end, ErrIter out_it) {
    using type = typename Iter::value_type;
    chunked_hash_map<std::string_view, uint32_t> freq;
    freq.reserve(std::distance(begin, end));
    for (const auto& r : boost::make_iterator_range(begin, end)) {
        freq[r.name()]++;
    }

    auto valid_range_end = std::partition(
      begin, end, [&freq](const type& item) { return freq[item.name()] == 1; });

    // We only want to respone _once_ for every duplicated user, so we will
    // iterate through the partitioned list and generate an error if we
    // encounter a user with a frequency greater than 1.  Once added, reset the
    // frequency to 1 to skip the user if found again
    for (auto it = valid_range_end; it != end; it++) {
        if (freq[it->name()] > 1) {
            *out_it = generate_error(
              *it,
              kafka::error_code::duplicate_resource,
              fmt::format(
                "Cannot describe SCRAM credentials for the same user twice in "
                "a "
                "single request: ",
                it->name));
            freq[it->name()] = 1;
            ++out_it;
        }
    }

    return valid_range_end;
}

template<typename Iter, typename OutIter>
void populate_results_with_users(
  Iter begin,
  Iter end,
  OutIter out_it,
  const security::credential_store& store) {
    using type = typename Iter::value_type;
    std::transform(begin, end, out_it, [&store](const type& item) {
        try {
            if (const auto& cred = store.get<security::scram_credential>(
                  security::credential_user{item.name()});
                cred.has_value()) {
                return describe_user_scram_credentials_result{
                  .user = item.name,
                  .credential_infos = {
                    scram_credential_to_credential_info(cred.value())}};
            } else {
                // store.get<T> returns std::nullopt if the user does not exist
                return generate_error(
                  item,
                  kafka::error_code::resource_not_found,
                  fmt::format(
                    "Cannot describe SCRAM credentials for non-existent user: "
                    "{}",
                    item.name));
            }
        } catch (...) {
            // store.get<T> throws if the user exists but is not of type T
            return generate_error(
              item,
              kafka::error_code::resource_not_found,
              fmt::format(
                "Cannot describe SCRAM credentials for non-existent user: {}",
                item.name));
        }
    });
}
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
    } else {
        const auto begin = request.data.users.value().begin();
        auto valid_range_end = validate_range_no_empty_users(
          begin,
          request.data.users.value().end(),
          std::back_inserter(res.data.results));
        auto duplicate_it = validate_range_duplicates(
          begin, valid_range_end, std::back_inserter(res.data.results));
        valid_range_end = duplicate_it;

        populate_results_with_users(
          begin,
          valid_range_end,
          std::back_inserter(res.data.results),
          ctx.credentials());
    }

    co_return co_await ctx.respond(std::move(res));
}
} // namespace kafka
