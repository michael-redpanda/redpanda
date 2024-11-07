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

#include "kafka/server/handlers/alter_user_scram_credentials.h"

#include "cluster/security_frontend.h"
#include "kafka/protocol/errors.h"
#include "kafka/protocol/logger.h"
#include "kafka/protocol/types.h"
#include "kafka/server/errors.h"
#include "kafka/server/handlers/details/security.h"
#include "model/timeout_clock.h"
#include "security/acl.h"
#include "security/credential_store.h"
#include "security/scram_algorithm.h"
#include "security/scram_credential.h"

#include <seastar/core/smp.hh>

#include <boost/container/flat_map.hpp>
#include <boost/range/iterator_range_core.hpp>

#include <algorithm>
#include <iterator>

namespace {

template<typename Iterator>
concept AlterUserScramCredentialsResultIterator
  = requires(Iterator it) { it = kafka::alter_user_scram_credentials_result{}; }
    && std::
      is_same_v<typename Iterator::iterator_category, std::output_iterator_tag>;

template<typename T>
requires kafka::details::KafkaUserName<T>
kafka::alter_user_scram_credentials_result
generate_error(const T& item, kafka::error_code code, const ss::sstring& msg) {
    return {.user = item.name, .error_code = code, .error_message = msg};
}

kafka::alter_user_scram_credentials_result generate_error(
  const kafka::scram_user_name& name,
  kafka::error_code code,
  const ss::sstring& msg) {
    return {.user = name, .error_code = code, .error_message = msg};
}

template<typename Iter, typename ErrIter>
requires kafka::details::KafkaUserName<typename Iter::value_type>
         && AlterUserScramCredentialsResultIterator<ErrIter>
Iter validate_range_no_empty_user(Iter begin, Iter end, ErrIter out_it) {
    using type = Iter::value_type;
    auto valid_range_end = std::partition(
      begin, end, [](const type& item) { return !item.name().empty(); });
    std::transform(valid_range_end, end, out_it, [](const type& item) {
        return generate_error(
          item,
          kafka::error_code::unacceptable_credential,
          "Username must not be empty");
    });

    return valid_range_end;
}

template<typename Iter, typename ErrIter>
requires AlterUserScramCredentialsResultIterator<ErrIter>
Iter validate_range_valid_scram_mech(Iter begin, Iter end, ErrIter out_it) {
    using type = Iter::value_type;
    auto valid_range_end = std::partition(begin, end, [](const type& item) {
        return kafka::details::kafka_to_security_mechanism(item.mechanism)
          .has_value();
    });
    std::transform(valid_range_end, end, out_it, [](const type& item) {
        return generate_error(
          item,
          kafka::error_code::unsupported_sasl_mechanism,
          "Unknown SCRAM mechanism");
    });
    return valid_range_end;
}

template<typename Iter, typename ErrIter>
requires AlterUserScramCredentialsResultIterator<ErrIter>
Iter validate_range_valid_iterations(
  Iter begin, Iter end, ErrIter out_it, int32_t max_iterations) {
    using type = Iter::value_type;
    const auto min_iterations = [](security::scram_algorithm_t scram_algo) {
        switch (scram_algo) {
        case security::scram_algorithm_t::sha256:
            return security::scram_sha256::min_iterations;
        case security::scram_algorithm_t::sha512:
            return security::scram_sha512::min_iterations;
        }
    };
    auto valid_range_end = std::partition(
      begin, end, [max_iterations, &min_iterations](const type& item) {
          return item.iterations >= min_iterations(
                   kafka::details::kafka_to_security_mechanism(item.mechanism)
                     .value())
                 && item.iterations <= max_iterations;
      });
    std::transform(
      valid_range_end, end, out_it, [max_iterations](const type& item) {
          return generate_error(
            item,
            kafka::error_code::unacceptable_credential,
            item.iterations > max_iterations ? "Too many iterations"
                                             : "Too few iterations");
      });
    return valid_range_end;
}

template<typename Iter, typename ErrIter>
requires AlterUserScramCredentialsResultIterator<ErrIter>
Iter valid_range_duplicates(Iter begin, Iter end, ErrIter out_it) {
    using type = Iter::value_type;

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
          "A user credential cannot be altered twice in the same request");
    });

    return valid_range_end;
}

template<typename IterUpsert, typename IterDelete, typename ErrIter>
requires AlterUserScramCredentialsResultIterator<ErrIter>
std::pair<IterUpsert, IterDelete> validate_range_no_shared_duplicates(
  IterUpsert ubegin,
  IterUpsert uend,
  IterDelete dbegin,
  IterDelete dend,
  ErrIter out_it) {
    using utype = IterUpsert::value_type;
    using dtype = IterDelete::value_type;
    boost::container::flat_map<kafka::scram_user_name, uint32_t> freq;
    freq.reserve(std::distance(ubegin, uend) + std::distance(dbegin, dend));

    for (auto& r : boost::make_iterator_range(ubegin, uend)) {
        std::for_each(dbegin, dend, [&r, &freq](const dtype& item) {
            if (r.name == item.name) {
                freq[r.name]++;
            }
        });
    }

    auto valid_upsert_end = std::partition(
      ubegin, uend, [&freq](const utype& item) {
          return freq[item.name] == 1;
      });
    auto valid_delete_end = std::partition(
      dbegin, dend, [&freq](const dtype& item) {
          return freq[item.name] == 1;
      });

    std::transform(freq.cbegin(), freq.cend(), out_it, [](const auto& r) {
        return generate_error(
          r.first,
          kafka::error_code::duplicate_resource,
          "A user credential cannot be altered twice in the same request");
    });

    for (auto& r : freq) {
        if (r.second > 1) {
            *out_it = generate_error(
              r.first,
              kafka::error_code::duplicate_resource,
              "A user credential cannot be altered twice in the same request");
            (void)++out_it;
        }
    }

    return {valid_upsert_end, valid_delete_end};
}

kafka::error_code map_security_error_code(std::error_code ec) {
    if (!ec) {
        return kafka::error_code::none;
    }

    if (ec.category() == cluster::error_category()) {
        return kafka::map_topic_error_code(cluster::errc(ec.value()));
    }

    return kafka::error_code::unknown_server_error;
}

} // namespace

namespace kafka {
template<>
ss::future<response_ptr> alter_user_scram_credentials_handler::handle(
  request_context ctx, ss::smp_service_group) {
    constexpr int32_t max_iterations = 16384;

    alter_user_scram_credentials_request request;
    request.decode(ctx.reader(), ctx.header().version);
    log_request(ctx.header(), request);
    alter_user_scram_credentials_response res;

    if (!ctx.authorized(
          security::acl_operation::alter, security::default_cluster_name)) {
        res.data.results.reserve(
          request.data.upsertions.size() + request.data.deletions.size());
        std::transform(
          request.data.upsertions.cbegin(),
          request.data.upsertions.cend(),
          std::back_inserter(res.data.results),
          [](const scram_credential_upsertion& upsertion) {
              return alter_user_scram_credentials_result{
                .user = upsertion.name,
                .error_code = error_code::cluster_authorization_failed,
                .error_message = ss::sstring{
                  error_code_to_str(error_code::cluster_authorization_failed)}};
          });
        std::transform(
          request.data.deletions.cbegin(),
          request.data.deletions.cend(),
          std::back_inserter(res.data.results),
          [](const scram_credential_deletion& deletion) {
              return alter_user_scram_credentials_result{
                .user = deletion.name,
                .error_code = error_code::cluster_authorization_failed,
                .error_message = ss::sstring{
                  error_code_to_str(error_code::cluster_authorization_failed)}};
          });
        co_return co_await ctx.respond(std::move(res));
    }

    auto upsert_begin = request.data.upsertions.begin();
    auto upsert_valid_range_end = validate_range_no_empty_user(
      upsert_begin,
      request.data.upsertions.end(),
      std::back_inserter(res.data.results));

    auto invalid_mech_it = validate_range_valid_scram_mech(
      upsert_begin,
      upsert_valid_range_end,
      std::back_inserter(res.data.results));
    upsert_valid_range_end = invalid_mech_it;

    auto invalid_iterations_it = validate_range_valid_iterations(
      upsert_begin,
      upsert_valid_range_end,
      std::back_inserter(res.data.results),
      max_iterations);
    upsert_valid_range_end = invalid_iterations_it;

    auto deletions_begin = request.data.deletions.begin();
    auto deletions_valid_range_end = validate_range_no_empty_user(
      deletions_begin,
      request.data.deletions.end(),
      std::back_inserter(res.data.results));

    auto deletions_invalid_mech_it = validate_range_valid_scram_mech(
      deletions_begin,
      deletions_valid_range_end,
      std::back_inserter(res.data.results));
    deletions_valid_range_end = deletions_invalid_mech_it;

    auto upsert_duplicates_it = valid_range_duplicates(
      upsert_begin,
      upsert_valid_range_end,
      std::back_inserter(res.data.results));
    upsert_valid_range_end = upsert_duplicates_it;

    auto delete_duplicates_it = valid_range_duplicates(
      deletions_begin,
      deletions_valid_range_end,
      std::back_inserter(res.data.results));
    deletions_valid_range_end = delete_duplicates_it;

    std::tie(upsert_duplicates_it, delete_duplicates_it)
      = validate_range_no_shared_duplicates(
        upsert_begin,
        upsert_valid_range_end,
        deletions_begin,
        deletions_valid_range_end,
        std::back_inserter(res.data.results));

    upsert_valid_range_end = upsert_duplicates_it;
    deletions_valid_range_end = delete_duplicates_it;

    const auto make_creds = [](const scram_credential_upsertion& u) {
        security::acl_principal p{security::principal_type::user, u.name};
        auto mech = details::kafka_to_security_mechanism(u.mechanism).value();
        switch (mech) {
        case security::scram_algorithm_t::sha256:
            return security::scram_sha256::make_credentials(
              std::move(p), u.salted_password, u.salt, u.iterations);
        case security::scram_algorithm_t::sha512:
            return security::scram_sha512::make_credentials(
              std::move(p), u.salted_password, u.salt, u.iterations);
        }
    };

    for (const auto& u :
         boost::make_iterator_range(upsert_begin, upsert_valid_range_end)) {
        security::credential_user user{u.name};

        auto user_exists = ctx.credentials().contains(user);
        auto creds = make_creds(u);
        std::error_code ec;

        if (user_exists) {
            vlog(klog.debug, "Updating SCRAM credentials for user {}", u.name);
            ec = co_await ctx.security_frontend().update_user(
              std::move(user),
              std::move(creds),
              model::timeout_clock::now() + 5s);
        } else {
            vlog(klog.debug, "Creating SCRAM credentials for user {}", u.name);
            ec = co_await ctx.security_frontend().create_user(
              std::move(user),
              std::move(creds),
              model::timeout_clock::now() + 5s);
        }
        vlog(
          klog.debug,
          "Results for updating/creating user {}: ({}:{})",
          u.name,
          ec,
          ec.message());

        res.data.results.emplace_back(alter_user_scram_credentials_result{
          .user = u.name, .error_code = map_security_error_code(ec)});
    }

    for (const auto& u : boost::make_iterator_range(
           deletions_begin, deletions_valid_range_end)) {
        security::credential_user user{u.name};

        vlog(klog.debug, "Deleting SCRAM credentials for user {}", u.name);
        auto ec = co_await ctx.security_frontend().delete_user(
          std::move(user), model::timeout_clock::now() + 5s);
        vlog(
          klog.debug,
          "Results for deleting user {}: ({}:{})",
          u.name,
          ec,
          ec.message());

        res.data.results.emplace_back(alter_user_scram_credentials_result{
          .user = u.name, .error_code = map_security_error_code(ec)});
    }

    co_return co_await ctx.respond(std::move(res));
}
} // namespace kafka
