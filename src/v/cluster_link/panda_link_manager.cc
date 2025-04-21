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

#include "cluster_link/panda_link_manager.h"

#include "cluster_link/logger.h"
#include "model/namespace.h"

namespace cluster_link {

manager::manager(
  model::node_id self,
  std::unique_ptr<panda_link_registry> registry,
  std::unique_ptr<panda_link_factory> factory)
  : _self(self)
  , _queue([](const std::exception_ptr& ex) {
      vlog(cllog.error, "unexpected panda link manager error: {}", ex);
  })
  , _registry(std::move(registry))
  , _factory(std::move(factory)) {}

ss::future<void> manager::start() {
    // Start the client
    return ss::now();
}

ss::future<void> manager::stop() {
    vlog(cllog.info, "Stopping panda link manager");
    co_await _queue.shutdown();
    vlog(cllog.info, "Stopped panda link manager");
}

void manager::on_link_change(model::panda_link_id id) {
    _queue.submit([this, id] { return handle_link_change(id); });
}

void manager::on_leadership_change(model::ntp ntp, ntp_leader is_leader) {
    vlog(cllog.trace, "ntp: {}, is_leader: {}", ntp, is_leader);
    if (ntp == model::controller_ntp) {
        on_controller_leadership_change(is_leader);
    } else {
        on_kafka_topic_leadership_change(std::move(ntp), is_leader);
    }
}

ss::future<> manager::handle_link_change(model::panda_link_id id) {
    vlog(cllog.trace, "handling link change for id {}", id);

    auto meta = _registry->lookup_by_id(id);
    auto it = _links.find(id);
    if (!meta) {
        vlog(cllog.debug, "Detected link going down for {}", id);

        if (it == _links.end()) {
            vlog(cllog.debug, "Link {} not found, already shut down?", id);
            co_return;
        }
        co_await it->second->stop();
        _links.erase(it);
        vlog(cllog.debug, "Link {} shut down", id);
        co_return;
    }

    if (it != _links.end()) {
        vlog(cllog.debug, "Link {} already exists, not yet updating", id);
        co_return;
    }

    vlog(
      cllog.debug,
      "Creating link {} named \"{}\" targeting {}",
      id,
      meta->name,
      meta->source_cluster_bootstrap_server);

    auto link = co_await _factory->create(
      meta->source_cluster_bootstrap_server, meta->mirrored_topics);
    co_await link->start();
    auto [links_it, _] = _links.emplace(id, std::move(link));
    if (_is_controller_leader) {
        vlog(cllog.debug, "Starting topic monitoring for link {}", id);
        co_await links_it->second->start_topic_monitoring();
    }
    vlog(
      cllog.info,
      "Link {} named \"{}\" targeting {} created",
      id,
      meta->name,
      meta->source_cluster_bootstrap_server);
}

void manager::on_controller_leadership_change(ntp_leader is_leader) {
    vlog(cllog.trace, "Detected controller leadership change: {}", is_leader);
    _is_controller_leader = is_leader;
    _queue.submit([this, is_leader] {
        return handle_controller_leadership_change(is_leader);
    });
}

void manager::on_kafka_topic_leadership_change(
  model::ntp ntp, ntp_leader is_leader) {
    _queue.submit([this, ntp = std::move(ntp), is_leader]() mutable {
        return handle_kafka_topic_leadership_change(std::move(ntp), is_leader);
    });
}

ss::future<>
manager::handle_controller_leadership_change(ntp_leader is_leader) {
    if (is_leader == ntp_leader::yes) {
        vlog(cllog.info, "Controller is leader, starting topic monitoring");
        for (auto& [_, link] : _links) {
            co_await link->start_topic_monitoring();
        }
    } else {
        vlog(cllog.info, "Controller is not leader, stopping topic monitoring");
        for (auto& [_, link] : _links) {
            co_await link->stop_topic_monitoring();
        }
    }
}

ss::future<> manager::handle_kafka_topic_leadership_change(
  model::ntp ntp, ntp_leader is_leader) {
    auto range = _links | std::views::filter([&](const auto& pair) {
                     const auto& link = pair.second;
                     return std::find(
                              link->mirrored_topics().begin(),
                              link->mirrored_topics().end(),
                              model::topic_namespace(ntp.ns, ntp.tp.topic))
                            != link->mirrored_topics().end();
                 });

    for (const auto& [id, link] : range) {
        if (is_leader == ntp_leader::yes) {
            vlog(
              cllog.debug,
              "Alerting panda link {} to start fetching topic {}",
              id,
              ntp);
            co_await link->start_ntp_mirroring(ntp);
        } else {
            vlog(
              cllog.debug,
              "Alerting panda link {} to stop fetching topic {}",
              id,
              ntp);
            co_await link->stop_ntp_mirroring(ntp);
        }
    }
}
} // namespace cluster_link
