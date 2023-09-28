/*
 * Copyright 2020 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#pragma once
#include "cluster/fwd.h"
#include "cluster/types.h"
#include "kafka/server/handlers/topics/types.h"
#include "kafka/server/handlers/topics/validators.h"
#include "model/timeout_clock.h"
#include "seastarx.h"

#include <boost/container/flat_map.hpp>

/// All of the Kafka Topic-related APIs have the same structure of
/// request/response messages. The request always contains list of
/// request specific properties tagged with topic name.
/// And additional fields depending on request type. The response contains
/// a list of errors for those topics for which requested operation failed.
/// The validation must be perform per 'topic' not the request as a whole.
/// This is a set of functions allowing to easily validate and generate errors
/// for topic request items.

namespace kafka {
template<typename T>
concept TopicRequestItem = requires(T item) {
    { item.name } -> std::convertible_to<model::topic_view>;
};
template<typename Iterator>
concept TopicResultIterator
  = requires(Iterator it) { it = creatable_topic_result{}; }
    && std::
      is_same_v<typename Iterator::iterator_category, std::output_iterator_tag>;

/// Generates failed creatable_topic_result for single topic request item
template<typename T>
requires TopicRequestItem<T>
creatable_topic_result
generate_error(T item, error_code code, const ss::sstring& msg) {
    return creatable_topic_result{
      .name = item.name,
      .error_code = code,
      .error_message = msg,
      .topic_config_error_code = code};
}

/// Generates successfull creatable_topic_result for single topic request item
template<typename T>
requires TopicRequestItem<T>
creatable_topic_result generate_successfull_result(T item) {
    return creatable_topic_result{
      .name = item.name, .error_code = error_code::none};
}

/// Validates topic requests items in range with predicate,
/// generate errors for not valid items and returns end of valid items range.
/// Generated errors are stored in other range beggining at out_it.
// clang-format off
template<typename Iter, typename ErrIter, typename Predicate>
    requires TopicRequestItem<typename Iter::value_type> &&
    TopicResultIterator<ErrIter> &&
    std::predicate<Predicate, std::iter_reference_t<Iter>>
// clang-format on
Iter validate_requests_range(
  Iter begin,
  Iter end,
  ErrIter out_it,
  error_code code,
  const ss::sstring& error_msg,
  Predicate&& p) {
    auto valid_range_end = std::partition(begin, end, p);
    std::transform(
      valid_range_end,
      end,
      out_it,
      [code, &error_msg](const typename Iter::value_type& item) {
          return generate_error(item, code, error_msg);
      });
    return valid_range_end;
}

/// Validates topic request items with validators from the ValidatorTypes
/// type list
template<typename Iter, typename ErrIter, typename... ValidatorTypes>
requires TopicRequestItem<typename Iter::value_type>
Iter validate_requests_range(
  Iter begin,
  Iter end,
  ErrIter err_it,
  validator_type_list<typename Iter::value_type, ValidatorTypes...>) {
    ((end = validate_requests_range(
        begin,
        end,
        err_it,
        ValidatorTypes::ec,
        ValidatorTypes::error_message,
        ValidatorTypes::template is_valid<typename Iter::value_type>)),
     ...);
    return end;
}

// Maps errors generated by cluster::controller to objects reperesenting
// Kafka protocol error message
void append_cluster_results(
  const std::vector<cluster::topic_result>&,
  std::vector<creatable_topic_result>&);

// Converts objects representing KafkaAPI message to objects consumed
// by cluster::controller API
// clang-format off
template<typename KafkaApiTypeIter>
requires TopicRequestItem<typename KafkaApiTypeIter::value_type> &&
requires(KafkaApiTypeIter it) {
    to_cluster_type(*it);
}
// clang-format on
auto to_cluster_type(KafkaApiTypeIter begin, KafkaApiTypeIter end)
  -> std::vector<decltype(to_cluster_type(*begin))> {
    std::vector<decltype(to_cluster_type(*begin))> cluster_types;
    cluster_types.reserve(std::distance(begin, end));
    std::transform(
      begin,
      end,
      std::back_inserter(cluster_types),
      [](const typename KafkaApiTypeIter::value_type& kafka_type) {
          return to_cluster_type(kafka_type);
      });
    return cluster_types;
}

/// Generate errors for all the request items that topic names
/// are duplicated within given range,
/// the errors are insterted in the range begginning at out_it
// clang-format off
template<typename Iter, typename ErrIter>
requires TopicRequestItem<typename Iter::value_type> &&
         TopicResultIterator<ErrIter>
// clang-format on
Iter validate_range_duplicates(Iter begin, Iter end, ErrIter out_it) {
    using type = typename Iter::value_type;
    boost::container::flat_map<model::topic_view, uint32_t> freq;
    freq.reserve(std::distance(begin, end));
    for (auto const& r : boost::make_iterator_range(begin, end)) {
        freq[r.name]++;
    }
    auto valid_range_end = std::partition(
      begin, end, [&freq](const type& item) { return freq[item.name] == 1; });
    std::transform(valid_range_end, end, out_it, [](const type& item) {
        return generate_error(
          item, error_code::invalid_request, "Duplicated topic");
    });
    return valid_range_end;
}

/// Generate NOT_CONTROLLER error for all the request items within given range
/// the errors are inserted in the range begginning at out_it
/// This pattern is used in every Admin request of Kafka protocol.
// clang-format off
template<typename Iter, typename ErrIter>
requires TopicRequestItem<typename Iter::value_type> &&
         TopicResultIterator<ErrIter>
// clang-format on
void generate_not_controller_errors(Iter begin, Iter end, ErrIter out_it) {
    std::transform(
      begin, end, out_it, [](const typename Iter::value_type& item) {
          return generate_error(
            item,
            error_code::not_controller,
            "Current node is not a cluster controller");
      });
}

// Wait for leaders of all topic partitons for given set of results
ss::future<std::vector<model::node_id>> wait_for_leaders(
  cluster::metadata_cache&,
  std::vector<cluster::topic_result>,
  model::timeout_clock::time_point);

ss::future<> wait_for_topics(
  cluster::metadata_cache&,
  std::vector<cluster::topic_result>,
  cluster::controller_api&,
  model::timeout_clock::time_point);

} // namespace kafka
