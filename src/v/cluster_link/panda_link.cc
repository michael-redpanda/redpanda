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

#include <fmt/ranges.h>

using kc = kafka::client::client;
using kc_config = kafka::client::configuration;

using namespace std::chrono_literals;

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
    co_await stop_ntp_mirroring();
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

ss::future<> panda_link::start_ntp_mirroring(model::ntp ntp) {
    auto _ = _gate.hold();
    if (_topic_mirroring.has_value()) {
        vlog(cllog.debug, "Topic mirroring already started, adding {}", ntp);
        _topic_mirroring->add_ntp(ntp);
        co_return;
    }
    vlog(cllog.debug, "Starting topic mirroring for ntp {}", ntp);
    absl::flat_hash_set<model::ntp> ntps;
    ntps.insert(ntp);
    _topic_mirroring.emplace(_client.get(), std::move(ntps));
    co_await _topic_mirroring->start();
}

ss::future<> panda_link::stop_ntp_mirroring() {
    auto _ = _gate.hold();
    if (_topic_mirroring.has_value()) {
        co_await _topic_mirroring->stop();
        _topic_mirroring.reset();
    }
}

ss::future<> panda_link::stop_ntp_mirroring(model::ntp ntp) {
    auto _ = _gate.hold();
    if (_topic_mirroring.has_value()) {
        vlog(cllog.debug, "Halting mirroring for ntp {}", ntp);
        _topic_mirroring->remove_ntp(ntp);
        if (_topic_mirroring->mirrored_ntps().empty()) {
            co_await stop_ntp_mirroring();
        }
    }
}

const std::vector<model::topic_namespace>& panda_link::mirrored_topics() const {
    return _mirrored_topics;
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

panda_link::topic_mirroring::topic_mirroring(
  kafka::client::client* client, absl::flat_hash_set<model::ntp> ntps)
  : _client(client)
  , _mirrored_ntps(std::move(ntps)) {}

ss::future<> panda_link::topic_mirroring::start() {
    vlog(cllog.trace, "Starting topic mirroring for ntps {}", _mirrored_ntps);
    ssx::spawn_with_gate(_gate, [this] { return mirror_topics(); });
    return ss::now();
}

ss::future<> panda_link::topic_mirroring::stop() {
    vlog(cllog.trace, "Stopping topic mirroring for ntps {}", _mirrored_ntps);
    _as.request_abort();
    co_await _gate.close();
}

const absl::flat_hash_set<model::ntp>&
panda_link::topic_mirroring::mirrored_ntps() const {
    return _mirrored_ntps;
}

void panda_link::topic_mirroring::add_ntp(model::ntp ntp) {
    _mirrored_ntps.insert(std::move(ntp));
}

void panda_link::topic_mirroring::remove_ntp(model::ntp ntp) {
    _mirrored_ntps.erase(ntp);
}

ss::future<> panda_link::topic_mirroring::mirror_topics() {
    while (!_as.abort_requested()) {
        vlog(cllog.trace, "mirror topics run loop: {}", _mirrored_ntps);
        auto offsets = co_await fetch_offsets();
        chunked_vector<ss::future<kafka::fetch_response>> fetch_futures;
        for (const auto& [ntp, offset] : offsets) {
            if (offset != model::offset(0)) {
                // auto fetch_offset = offset - model::offset(1);
                auto fetch_offset = model::offset{0};
                vlog(
                  cllog.debug,
                  "Fetching offset {} from ntp {}",
                  fetch_offset,
                  ntp);
                fetch_futures.emplace_back(_client->fetch_partition(
                  ntp.tp, fetch_offset, 1024 * 1024, 5s));
            }
        }

        auto fetch_results = co_await ss::when_all(
          fetch_futures.begin(), fetch_futures.end());
        for (auto& f : fetch_results) {
            try {
                auto res = f.get();
                if (res.data.error_code != kafka::error_code::none) {
                    vlog(
                      cllog.warn,
                      "Error in fetch response: {}",
                      res.data.error_code);
                    continue;
                }
                const auto& topics = res.data.topics;
                if (topics.size() != 1 || topics[0].partitions.size() != 1) {
                    vlog(
                      cllog.warn,
                      "Invalid fetch response: {}",
                      res.data.error_code);
                    continue;
                }
                const auto& part = topics[0].partitions[0];
                if (part.error_code != kafka::error_code::none) {
                    vlog(
                      cllog.warn,
                      "Error in fetch response: {}",
                      part.error_code);
                    continue;
                }
                vlog(cllog.info, "Fetch response HWM: {}", part.high_watermark);
                if (part.records.has_value()) {
                    auto batch_size = part.records->size_bytes();
                    auto is_end_of_stream = part.records->is_end_of_stream();
                    auto last_offset = part.records->last_offset();
                    vlog(
                      cllog.info,
                      "batch_size: {}, is_end_of_stream: {}, last_offset: {}",
                      batch_size,
                      is_end_of_stream,
                      last_offset);
                    // Process the batch here

                } else {
                    vlog(cllog.warn, "No records in fetch response");
                }
            } catch (const std::exception& e) {
                vlog(cllog.error, "Error fetching topic: {}", e.what());
            }
        }
        co_await ss::sleep_abortable(std::chrono::seconds(5), _as);
    }
}

ss::future<absl::flat_hash_map<model::ntp, model::offset>>
panda_link::topic_mirroring::fetch_offsets() {
    absl::flat_hash_map<model::ntp, model::offset> offsets;
    chunked_vector<ss::future<kafka::list_offsets_response>>
      list_offsets_futures;
    list_offsets_futures.reserve(_mirrored_ntps.size());
    vlog(cllog.trace, "fetching offsets for ntps");
    for (const auto& ntp : _mirrored_ntps) {
        list_offsets_futures.emplace_back(_client->list_offsets(ntp.tp));
    }
    auto list_offset_results = co_await ss::when_all(
      list_offsets_futures.begin(), list_offsets_futures.end());
    for (auto& f : list_offset_results) {
        try {
            auto res = f.get();
            if (res.data.topics.empty()) {
                vlog(
                  cllog.warn,
                  "No topics found in list offsets response: {}",
                  res);
                continue;
            }
            auto topic_it = std::ranges::find_if(
              res.data.topics,
              [](const auto& t) { return t.partitions.size() > 0; });
            if (topic_it == res.data.topics.end()) {
                vlog(
                  cllog.warn,
                  "No partitions found in list offsets response: {}",
                  res);
                continue;
            }
            auto partition_it = std::ranges::find_if(
              topic_it->partitions, [](const auto& p) {
                  return p.error_code != kafka::error_code::none;
              });
            if (partition_it != topic_it->partitions.end()) {
                vlog(
                  cllog.warn,
                  "Error in list offsets response: {}",
                  partition_it->error_code);
            }
            model::ntp ntp(
              model::kafka_namespace,
              res.data.topics[0].name,
              res.data.topics[0].partitions[0].partition_index);
            vlog(
              cllog.info,
              "Offset for {}: {}",
              ntp,
              res.data.topics[0].partitions[0].offset);
            offsets.emplace(ntp, res.data.topics[0].partitions[0].offset);
        } catch (const std::exception& e) {
            vlog(cllog.error, "Error fetching offsets: {}", e.what());
        }
    }

    co_return offsets;
}

} // namespace cluster_link
