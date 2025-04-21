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

#include "cluster_link/panda_link.h"

#include "base/vlog.h"
#include "cluster_link/logger.h"
#include "kafka/protocol/metadata.h"
#include "ssx/future-util.h"
#include "transform/rpc/deps.h"
#include "utils/unresolved_address.h"

#include <seastar/util/later.hh>

using kc = kafka::client::client;
using kc_config = kafka::client::configuration;

namespace cluster_link {
panda_link::panda_link(
  std::vector<net::unresolved_address> source_broker_bootstrap_servers,
  std::vector<model::topic_namespace> mirrored_topics,
  std::unique_ptr<transform::rpc::topic_metadata_cache> topic_metadata,
  std::unique_ptr<transform::rpc::topic_creator> topic_creator)
  : _source_broker_bootstrap_servers(std::move(source_broker_bootstrap_servers))
  , _mirrored_topics(std::move(mirrored_topics))
  , _topic_metadata(std::move(topic_metadata))
  , _topic_creator(std::move(topic_creator))
  , _kc_config(create_kafka_client_config(_source_broker_bootstrap_servers)) {}

ss::future<> panda_link::start() {
    vlog(
      cllog.trace,
      "Starting panda link to {}",
      _source_broker_bootstrap_servers);
    _client = std::make_unique<kc>(
      config::to_yaml(_kc_config, config::redact_secrets::no));
    co_await _client->connect();
}

ss::future<> panda_link::stop() {
    vlog(
      cllog.trace,
      "Stopping panda link to {}",
      _source_broker_bootstrap_servers);
    co_await stop_topic_monitoring();
    if (_client) {
        co_await _client->stop();
        _client.reset();
    }
    co_await _gate.close();
    vlog(
      cllog.trace,
      "Panda link to {} stopped",
      _source_broker_bootstrap_servers);
}

ss::future<> panda_link::start_topic_monitoring() {
    auto _ = _gate.hold();
    vlog(
      cllog.trace, "Starting topic monitoring for topics {}", _mirrored_topics);
    if (_topic_monitor.has_value()) {
        vlog(cllog.info, "Topic monitor already started");
        co_return;
    }
    _topic_monitor.emplace(
      _client.get(),
      std::chrono::seconds(5),
      _mirrored_topics,
      _topic_metadata.get(),
      _topic_creator.get());
    co_await _topic_monitor->start();
}

ss::future<> panda_link::stop_topic_monitoring() {
    auto _ = _gate.hold();
    vlog(
      cllog.trace, "Stopping topic monitoring for topics {}", _mirrored_topics);
    if (!_topic_monitor.has_value()) {
        vlog(cllog.info, "Topic monitor not started");
        co_return;
    }
    co_await _topic_monitor->stop();
    _topic_monitor.reset();
}

kc_config panda_link::create_kafka_client_config(
  const std::vector<net::unresolved_address>& source_broker_bootstrap_servers) {
    kc_config cfg;
    cfg.brokers.set_value(source_broker_bootstrap_servers);
    return cfg;
}

panda_link::topic_monitor::topic_monitor(
  kafka::client::client* client,
  ss::lowres_clock::duration interval,
  std::vector<model::topic_namespace> topics,
  transform::rpc::topic_metadata_cache* topic_metadata,
  transform::rpc::topic_creator* topic_creator)
  : _client(client)
  , _monitor_interval(interval)
  , _topics(std::move(topics))
  , _topic_metadata(topic_metadata)
  , _topic_creator(topic_creator) {}

ss::future<> panda_link::topic_monitor::start() {
    vlog(cllog.trace, "Starting topic monitor");
    ssx::spawn_with_gate(_gate, [this] { return monitor_topics(); });
    return ss::now();
}

ss::future<> panda_link::topic_monitor::stop() {
    vlog(cllog.trace, "Stopping topic monitor");
    _as.request_abort();
    co_await _gate.close();
}

ss::future<> panda_link::topic_monitor::monitor_topics() {
    const auto create_metadata_request =
      [](const std::vector<model::topic_namespace>& topics) {
          chunked_vector<kafka::metadata_request_topic> req_topics;
          req_topics.reserve(topics.size());
          std::ranges::for_each(topics, [&req_topics](const auto& tp_ns) {
              req_topics.emplace_back(
                kafka::metadata_request_topic{.name = tp_ns.tp});
          });
          return kafka::metadata_request{
            .data = {
              .topics = std::move(req_topics),
              .allow_auto_topic_creation = false,
              .include_cluster_authorized_operations = false,
              .include_topic_authorized_operations = false,
            },
            .list_all_topics = false};
      };
    while (!_as.abort_requested()) {
        vlog(cllog.trace, "monitor topics loop run");

        auto resp = co_await _client->get_metadata(
          create_metadata_request(_topics));
        vlog(cllog.trace, "metadata response: {}", resp);
        absl::flat_hash_map<
          model::topic_namespace,
          kafka::describe_configs_response>
          configs;
        configs.reserve(_topics.size());
        for (const auto& topic : _topics) {
            auto resp = co_await _client->describe_topic(
              topic.tp, std::nullopt);
            vlog(
              cllog.trace, "describe topic response for {}: {}", topic, resp);
            configs.emplace(topic, std::move(resp));
        }
        for (const auto& topic : _topics) {
            auto metadata_it = std::ranges::find_if(
              resp.data.topics,
              [&topic](const auto& t) { return t.name == topic.tp; });
            if (metadata_it == resp.data.topics.end()) {
                vlog(
                  cllog.warn, "Topic {} not found in metadata response", topic);
                continue;
            }
            auto local_topic_metadata = _topic_metadata->find_topic_cfg(topic);
            if (!local_topic_metadata.has_value()) {
                vlog(cllog.warn, "Topic {} not found locally", topic);
                continue;
            }
            auto remote_partition_count = static_cast<int32_t>(
              metadata_it->partitions.size());
            if (
              remote_partition_count != local_topic_metadata->partition_count) {
                vlog(
                  cllog.info,
                  "Topic {} partition count has changed: {}",
                  topic,
                  remote_partition_count);
                if (
                  remote_partition_count
                  < local_topic_metadata->partition_count) {
                    vlog(
                      cllog.warn,
                      "Shrinking partition count not supported: {} < {}",
                      remote_partition_count,
                      local_topic_metadata->partition_count);
                    continue;
                }
                auto res = co_await _topic_creator->create_partitions(
                  {topic, remote_partition_count});
                if (res != cluster::errc::success) {
                    vlog(
                      cllog.warn,
                      "Failed to create partitions for topic {}: {}",
                      topic,
                      res);
                    continue;
                } else {
                    vlog(
                      cllog.info,
                      "Successfully updated partition count for topic {} to {}",
                      topic,
                      remote_partition_count);
                }
            }
        }
        co_await ss::sleep_abortable(_monitor_interval, _as);
    }
}

} // namespace cluster_link
