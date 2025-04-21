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
#include "ssx/future-util.h"
#include "utils/unresolved_address.h"

#include <seastar/util/later.hh>

using kc = kafka::client::client;
using kc_config = kafka::client::configuration;

namespace cluster_link {
panda_link::panda_link(
  std::vector<net::unresolved_address> source_broker_bootstrap_servers,
  std::vector<model::topic> mirrored_topics)
  : _source_broker_bootstrap_servers(std::move(source_broker_bootstrap_servers))
  , _mirrored_topics(std::move(mirrored_topics))
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
    _topic_monitor.emplace(_client.get(), std::chrono::seconds(5));
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
  kafka::client::client* client, ss::lowres_clock::duration interval)
  : _client(client)
  , _monitor_interval(interval) {}

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
    while (!_as.abort_requested()) {
        vlog(cllog.trace, "monitor topics loop run");
        auto resp = co_await _client->get_metadata();
        vlog(cllog.trace, "metadata response: {}", resp);
        co_await ss::sleep_abortable(_monitor_interval, _as);
    }
}

} // namespace cluster_link
