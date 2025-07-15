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

#pragma once

#include "cluster/cluster_link/errc.h"
#include "cluster_link/model/types.h"
#include "kafka/client/cluster.h"
#include "kafka/client/configuration.h"
#include "kafka/data/rpc/deps.h"
#include "utils/prefix_logger.h"

namespace kafka::client {

class link_registry {
public:
    link_registry() = default;
    link_registry(const link_registry&) = delete;
    link_registry(link_registry&&) = delete;
    link_registry& operator=(const link_registry&) = delete;
    link_registry& operator=(link_registry&&) = delete;
    virtual ~link_registry() = default;

    virtual std::optional<::cluster_link::model::metadata>
      find_link_by_id(::cluster_link::model::id_t) const = 0;

    virtual ss::future<::cluster::cluster_link::errc> add_mirror_topic(
      ::cluster_link::model::id_t,
      ::cluster_link::model::add_mirror_topic_cmd,
      model::timeout_clock::time_point)
      = 0;
};

class cluster_link {
public:
    cluster_link(
      const client_configuration& config,
      std::unique_ptr<link_registry> link_registry,
      std::unique_ptr<data::rpc::topic_metadata_cache> topic_metadata_cache);

    /// Connects to all brokers
    ss::future<> connect();
    /// Disconnects from all brokers
    ss::future<> stop() noexcept;

    /// This will:
    /// - grab the list of topics from the remote cluster
    /// - use the filters in the cluster link table to filter out the topics to
    /// mirror
    /// - for every topic that isn't yet mirrored, add that topic to the mirror
    /// topic table
    ss::future<> update_mirror_topic_state(::cluster_link::model::id_t link_id);

private:
    prefix_logger& logger();

    ss::future<describe_configs_response> describe_topic(
      model::topic,
      std::optional<chunked_vector<ss::sstring>> configuration_keys
      = std::nullopt);

private:
    std::unique_ptr<link_registry> _link_registry;
    std::unique_ptr<data::rpc::topic_metadata_cache> _topic_metadata_cache;
    prefix_logger _logger;
    cluster _cluster;

    std::optional<api_version_range> _supported_api_versions_describe_configs;

    bool _is_started{false};
    ss::abort_source _as;
};
} // namespace kafka::client
