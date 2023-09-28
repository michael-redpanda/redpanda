/*
 * Copyright 2023 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#include "kafka/server/handlers/topics/validators.h"

namespace kafka {
template<>
bool custom_partition_assignment_negative_partition_count::is_valid(
  const creatable_topic& c) {
    if (!c.assignments.empty()) {
        return c.num_partitions == -1 && c.replication_factor == -1;
    }

    return true;
};

template<>
bool replicas_diversity::is_valid(const creatable_topic& c) {
    if (c.assignments.empty()) {
        return true;
    }
    return std::all_of(
      c.assignments.begin(),
      c.assignments.end(),
      [](const creatable_replica_assignment& cra) {
          auto ids = cra.broker_ids;
          std::sort(ids.begin(), ids.end());
          auto last = std::unique(ids.begin(), ids.end());
          return ids.size() == (size_t)std::distance(ids.begin(), last);
      });
}

template<>
bool all_replication_factors_are_the_same::is_valid(const creatable_topic& c) {
    if (c.assignments.empty()) {
        return true;
    }
    auto replication_factor = c.assignments.front().broker_ids.size();
    return std::all_of(
      c.assignments.begin(),
      c.assignments.end(),
      [replication_factor](const creatable_replica_assignment& cra) {
          return cra.broker_ids.size() == replication_factor;
      });
}

template<>
bool partition_count_must_be_positive::is_valid(const creatable_topic& c) {
    if (!c.assignments.empty()) {
        return true;
    }

    return c.num_partitions > 0;
}

template<>
bool replication_factor_must_be_odd::is_valid(const creatable_topic& c) {
    if (!c.assignments.empty()) {
        return true;
    }

    return (c.replication_factor % 2) == 1;
}

template<>
bool replication_factor_must_be_odd::is_valid(
  const incremental_alter_configs_resource& r) {
    auto config_entries = config_map(r.configs);

    if (auto it = config_entries.find(topic_property_replication_factor);
        it != config_entries.end()) {
        return boost::lexical_cast<int32_t>(std::get<1>(it->second)) % 2 == 1;
    }
    return true;
}

template<>
bool replication_factor_must_be_positive::is_valid(const creatable_topic& c) {
    if (!c.assignments.empty()) {
        return true;
    }

    return c.replication_factor > 0;
}

template<>
bool unsupported_configuration_entries::is_valid(const creatable_topic& c) {
    auto config_entries = config_map(c.configs);
    auto end = config_entries.end();
    return end == config_entries.find("min.insync.replicas")
           && end == config_entries.find("flush.messages")
           && end == config_entries.find("flush.ms");
}

template<>
bool remote_read_and_write_are_not_supported_for_read_replica::is_valid(
  const creatable_topic& c) {
    auto config_entries = config_map(c.configs);
    auto end = config_entries.end();
    bool is_recovery = (config_entries.find(topic_property_recovery) != end);
    bool is_read_replica
      = (config_entries.find(topic_property_read_replica) != end);
    bool remote_read = (config_entries.find(topic_property_remote_read) != end);
    bool remote_write
      = (config_entries.find(topic_property_remote_write) != end);

    if (is_read_replica && (remote_read || remote_write || is_recovery)) {
        return false;
    }
    return true;
}

template<>
bool batch_max_bytes_limits::is_valid(const creatable_topic& c) {
    auto it = std::find_if(
      c.configs.begin(),
      c.configs.end(),
      [](const createable_topic_config& cfg) {
          return cfg.name == topic_property_max_message_bytes;
      });
    if (it != c.configs.end() && it->value.has_value()) {
        return boost::lexical_cast<int32_t>(it->value.value()) > 0;
    }

    return true;
}

template<>
bool subject_name_strategy_validator::is_valid(const creatable_topic& c) {
    return std::all_of(
      c.configs.begin(), c.configs.end(), [](createable_topic_config const& v) {
          return !is_sns_config(v) || !v.value.has_value()
                 || is_valid_sns(v.value.value());
      });
}

template<>
template<>
bool configuration_value_validator<
  compression_type_validator_details>::is_valid(const creatable_topic& c) {
    auto config_entries = config_map(c.configs);
    auto end = config_entries.end();

    auto iter = config_entries.find(
      compression_type_validator_details::config_name);

    if (end == iter) {
        return true;
    }

    try {
        boost::lexical_cast<
          typename compression_type_validator_details::validated_type>(
          iter->second);
        return true;
    } catch (...) {
        return false;
    }
}

template<>
template<>
bool configuration_value_validator<
  compaction_strategy_validator_details>::is_valid(const creatable_topic& c) {
    auto config_entries = config_map(c.configs);
    auto end = config_entries.end();

    auto iter = config_entries.find(
      compaction_strategy_validator_details::config_name);

    if (end == iter) {
        return true;
    }

    try {
        boost::lexical_cast<
          typename compaction_strategy_validator_details::validated_type>(
          iter->second);
        return true;
    } catch (...) {
        return false;
    }
}

template<>
template<>
bool configuration_value_validator<timestamp_type_validator_details>::is_valid(
  const creatable_topic& c) {
    auto config_entries = config_map(c.configs);
    auto end = config_entries.end();

    auto iter = config_entries.find(
      timestamp_type_validator_details::config_name);

    if (end == iter) {
        return true;
    }

    try {
        boost::lexical_cast<
          typename timestamp_type_validator_details::validated_type>(
          iter->second);
        return true;
    } catch (...) {
        return false;
    }
}

template<>
template<>
bool configuration_value_validator<cleanup_policy_validator_details>::is_valid(
  const creatable_topic& c) {
    auto config_entries = config_map(c.configs);
    auto end = config_entries.end();

    auto iter = config_entries.find(
      cleanup_policy_validator_details::config_name);

    if (end == iter) {
        return true;
    }

    try {
        boost::lexical_cast<
          typename cleanup_policy_validator_details::validated_type>(
          iter->second);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace kafka
