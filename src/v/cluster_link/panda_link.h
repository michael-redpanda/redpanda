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

#include "base/seastarx.h"
#include "kafka/client/client.h"
#include "kafka/client/configuration.h"
#include "transform/rpc/deps.h"
#include "utils/unresolved_address.h"

#include <seastar/core/future.hh>
#include <seastar/core/sstring.hh>

namespace cluster_link {
class panda_link {
public:
    explicit panda_link(
      std::vector<net::unresolved_address> _source_broker_bootstrap_servers,
      std::vector<model::topic> mirrored_topics,
      std::unique_ptr<transform::rpc::topic_metadata_cache> topic_metadata);
    panda_link(const panda_link&) = delete;
    panda_link& operator=(const panda_link&) = delete;
    panda_link(panda_link&&) = delete;
    panda_link& operator=(panda_link&&) = delete;

    virtual ~panda_link() = default;

    virtual ss::future<> start();
    virtual ss::future<> stop();

    virtual ss::future<> start_topic_monitoring();
    virtual ss::future<> stop_topic_monitoring();

private:
    static kafka::client::configuration
    create_kafka_client_config(const std::vector<net::unresolved_address>&
                                 source_broker_bootstrap_servers);

    class topic_monitor {
    public:
        topic_monitor(
          kafka::client::client* client,
          ss::lowres_clock::duration interval,
          std::vector<model::topic> topics,
          transform::rpc::topic_metadata_cache* topic_metadata);
        ss::future<> start();
        ss::future<> stop();

    private:
        ss::future<> monitor_topics();

    private:
        kafka::client::client* _client;
        ss::lowres_clock::duration _monitor_interval{std::chrono::seconds(5)};
        std::vector<model::topic> _topics;
        transform::rpc::topic_metadata_cache* _topic_metadata;

        ss::abort_source _as;
        ss::gate _gate;
    };

private:
    std::vector<net::unresolved_address> _source_broker_bootstrap_servers;
    std::vector<model::topic> _mirrored_topics;
    std::unique_ptr<transform::rpc::topic_metadata_cache> _topic_metadata;
    kafka::client::configuration _kc_config;
    std::unique_ptr<kafka::client::client> _client;
    std::optional<topic_monitor> _topic_monitor;
    ss::gate _gate;
};
} // namespace cluster_link
