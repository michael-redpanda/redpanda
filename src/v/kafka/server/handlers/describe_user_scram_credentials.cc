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

#include "kafka/protocol/describe_user_scram_credentials.h"
#include "kafka/protocol/types.h"
#include "kafka/server/handlers/details/security.h"
#include "security/acl.h"
#include "security/credential_store.h"
#include "security/scram_credential.h"
#include "ssx/sformat.h"

#include <boost/container/flat_map.hpp>

#include <algorithm>
#include <concepts>
#include <iterator>

namespace {

template<typename Iterator>
concept DescribeUserScramCredentialsResultIterator
  = requires(
      Iterator it) { it = kafka::describe_user_scram_credentials_result{}; }
    && std::
      is_same_v<typename Iterator::iterator_category, std::output_iterator_tag>;

template<typename T>
requires kafka::details::KafkaUserName<T>
kafka::describe_user_scram_credentials_result
generate_error(const T& item, kafka::error_code code, const ss::sstring& msg) {
    return {.user = item.name, .error_code = code, .error_message = msg};
}

template<typename Iter, typename ErrIter>
requires kafka::details::KafkaUserName<typename Iter::value_type>
         && DescribeUserScramCredentialsResultIterator<ErrIter>
Iter validate_range_user_exists(
  Iter begin,
  Iter end,
  ErrIter out_it,
  const security::credential_store& store) {
    using type = typename Iter::value_type;
    auto valid_range_end = std::partition(
      begin, end, [&store](const type& item) {
          try {
              // Only want to return users that exist in the store _and_ are
              // scram credentialled
              auto val = store.get<security::scram_credential>(
                security::credential_user{item.name()});
              return val.has_value();
          } catch (...) {
              return false;
          }
      });

    std::transform(valid_range_end, end, out_it, [](const type& item) {
        return generate_error(
          item,
          kafka::error_code::resource_not_found,
          ssx::sformat(
            "Cannot describe SCRAM credentials for non-existent user: ",
            item.name));
    });

    return valid_range_end;
}

template<typename Iter, typename ErrIter>
requires kafka::details::KafkaUserName<typename Iter::value_type>
         && DescribeUserScramCredentialsResultIterator<ErrIter>
Iter validate_range_duplicates(Iter begin, Iter end, ErrIter out_it) {
    using type = typename Iter::value_type;
    boost::container::flat_map<kafka::scram_user_name, uint32_t> freq;
    freq.reserve(std::distance(begin, end));
    for (const auto& r : boost::make_iterator_range(begin, end)) {
        freq[r.name]++;
    }
    auto valid_range_end = std::partition(
      begin, end, [&freq](const type& item) { return freq[item.name] == 1; });

    std::transform(valid_range_end, end, out_it, [](const type& item) {
        return generate_error(
          item,
          kafka::error_code::duplicate_resource,
          ssx::sformat(
            "Cannot describe SCRAM credentials for the same user twice in a "
            "single request: ",
            item.name));
    });

    return valid_range_end;
}

} // namespace

namespace kafka {
template<>
ss::future<response_ptr> describe_user_scram_credentials_handler::handle(
  request_context ctx, ss::smp_service_group) {
    describe_user_scram_credentials_request request;
    request.decode(ctx.reader(), ctx.header().version);
    log_request(ctx.header(), request);

    describe_user_scram_credentials_response res;

    if (!ctx.authorized(
          security::acl_operation::describe, security::default_cluster_name)) {
        res.data.error_code = error_code::cluster_authorization_failed;
        res.data.error_message = ss::sstring{
          error_code_to_str(error_code::cluster_authorization_failed)};
        return ctx.respond(std::move(res));
    }

    if (!ctx.audit()) {
        res.data.error_code = error_code::broker_not_available;
        res.data.error_message = "Broker not available - audit system failure";
        return ctx.respond(std::move(res));
    }

    auto list_all_users = !request.data.users.has_value()
                          || request.data.users.value().empty();

    const auto all_scram_users =
      [](const security::credential_store::container_type::value_type& t)
      -> bool {
        return ss::visit(
          t.second, [](const security::scram_credential&) { return true; });
    };

    if (list_all_users) {
        for (auto c : ctx.credentials().range(all_scram_users)) {
            const auto& creds = std::get<security::scram_credential>(c.second);
            res.data.results.emplace_back(
              describe_user_scram_credentials_result{
                .user = c.first,
                .credential_infos = {credential_info{

                  .mechanism = details::security_to_kafka_mechanism(
                    creds.algorithm()),
                  .iterations = creds.iterations(),
                }}});
        }
    } else {
        auto begin = request.data.users.value().begin();
        auto valid_range_end = validate_range_user_exists(
          begin,
          request.data.users.value().end(),
          std::back_inserter(res.data.results),
          ctx.credentials());
        auto duplicate_it = validate_range_duplicates(
          begin, valid_range_end, std::back_inserter(res.data.results));
        valid_range_end = duplicate_it;

        for (const auto& user :
             boost::make_iterator_range(begin, valid_range_end)) {
            const auto& creds
              = ctx.credentials().get<security::scram_credential>(
                security::credential_user{user.name()});
            res.data.results.emplace_back(
              describe_user_scram_credentials_result{
                .user = user.name(),
                .credential_infos = {credential_info{
                  .mechanism = details::security_to_kafka_mechanism(
                    creds.value().algorithm()),
                  .iterations = creds.value().iterations(),
                }}});
        }
    }

    return ctx.respond(std::move(res));
}
} // namespace kafka
