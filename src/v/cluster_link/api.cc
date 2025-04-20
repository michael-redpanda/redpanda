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

#include "cluster_link/api.h"

#include "base/outcome.h"
#include "cluster/panda_link_frontend.h"
#include "cluster_link/logger.h"
#include "cluster_link/panda_link_manager.h"
#include "kafka/client/client.h"
#include "kafka/client/exceptions.h"
#include "model/panda_link.h"
#include "utils/unresolved_address.h"

#include <seastar/util/later.hh>

namespace cluster_link {
using kc_config = kafka::client::configuration;
using kc = kafka::client::client;
namespace {
constexpr auto metadata_timeout = std::chrono::seconds(1);

class pl_factory : public panda_link_factory {
public:
    ss::future<std::unique_ptr<panda_link>>
    create(std::vector<net::unresolved_address> source_broker_bootstrap_servers)
      override {
        co_return std::make_unique<panda_link>(
          std::move(source_broker_bootstrap_servers));
    }
};

std::unique_ptr<kc> create_kafka_client(
  const std::vector<net::unresolved_address>& source_broker_bootstrap_servers) {
    kc_config cfg;
    cfg.brokers.set_value(source_broker_bootstrap_servers);
    return std::make_unique<kc>(
      config::to_yaml(cfg, config::redact_secrets::no));
}

ss::future<
  result<absl::flat_hash_map<model::topic, kafka::describe_configs_response>>>
get_topic_configs(const model::panda_link_metadata& meta) {
    try {
        vlog(
          cllog.debug, "Attempting to get topic config for link {}", meta.name);
        auto client = create_kafka_client(meta.source_cluster_bootstrap_server);
        co_await client->connect();
        auto topics = meta.mirrored_topics;
        absl::flat_hash_map<model::topic, kafka::describe_configs_response>
          configs;
        for (const auto& topic : topics) {
            vlog(cllog.trace, "Getting config for topic {}", topic);
            auto response = co_await client->describe_topic(
              topic, std::nullopt);
            vlog(cllog.trace, "Got config for topic {}: {}", topic, response);
            configs.emplace(topic, std::move(response));
        }
        co_await client->stop();
        client.reset(nullptr);
        co_return configs;
    } catch (const kafka::client::topic_error& e) {
        co_return kafka::make_error_code(e.error);
    } catch (const kafka::client::broker_error& e) {
        co_return kafka::make_error_code(e.error);
    } catch (const std::exception& e) {
        co_return kafka::make_error_code(
          kafka::error_code::unknown_server_error);
    } catch (...) {
        co_return kafka::make_error_code(
          kafka::error_code::unknown_server_error);
    }
}

} // namespace

class panda_link_registry_adapter : public panda_link_registry {
public:
    explicit panda_link_registry_adapter(cluster::panda_link_frontend* plf)
      : _plf(plf) {}

    std::optional<model::panda_link_metadata>
    lookup_by_id(model::panda_link_id id) const override {
        return _plf->lookup_panda_link(id);
    }

private:
    cluster::panda_link_frontend* _plf;
};

service::service(
  model::node_id self, ss::sharded<cluster::panda_link_frontend>* pl_frontend)
  : _self(self)
  , _pl_frontend(pl_frontend) {}

service::~service() = default;

ss::future<> service::start() {
    _manager = std::make_unique<manager>(
      _self,
      std::make_unique<panda_link_registry_adapter>(&_pl_frontend->local()),
      std::make_unique<pl_factory>());

    co_await _manager->start();

    register_notifications();
}

ss::future<> service::stop() {
    unregister_notifications();
    co_await _gate.close();

    if (_manager) {
        co_await _manager->stop();
    }
}

ss::future<std::error_code>
service::create_link(model::panda_link_metadata meta) {
    auto _ = _gate.hold();
    vlog(
      cllog.info,
      "attempting to create a link named \"{}\" to {}",
      meta.name,
      meta.source_cluster_bootstrap_server);

    auto cfgs_rv = co_await get_topic_configs(meta);
    if (cfgs_rv.has_error()) {
        vlog(
          cllog.error,
          "failed to get topic configs for link {}: {}",
          meta.name,
          cfgs_rv.error().message());
        co_return cfgs_rv.assume_error();
    }
    auto cfgs = std::move(cfgs_rv).assume_value();

    auto name = meta.name;
    auto ec = co_await _pl_frontend->local().upsert_panda_link(
      std::move(meta), model::timeout_clock::now() + metadata_timeout);
    vlog(cllog.debug, "deploying link {} result: {}", name, ec);
    co_return cluster::make_error_code(ec);
}

void service::register_notifications() {
    auto pl_notif_id = _pl_frontend->local().register_for_updates(
      [this](model::panda_link_id id) { _manager->on_link_change(id); });
    _notification_cleanups.emplace_back([this, pl_notif_id] {
        _pl_frontend->local().unregister_for_updates(pl_notif_id);
    });
}

void service::unregister_notifications() { _notification_cleanups.clear(); }
} // namespace cluster_link
