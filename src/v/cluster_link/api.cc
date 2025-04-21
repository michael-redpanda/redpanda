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
#include "cluster/partition_manager.h"
#include "cluster_link/logger.h"
#include "cluster_link/panda_link_manager.h"
#include "kafka/client/client.h"
#include "kafka/client/exceptions.h"
#include "kafka/server/handlers/topics/types.h"
#include "model/panda_link.h"
#include "transform/rpc/deps.h"
#include "utils/unresolved_address.h"

#include <seastar/util/later.hh>

namespace cluster_link {
using kc_config = kafka::client::configuration;
using kc = kafka::client::client;
namespace {
constexpr auto metadata_timeout = std::chrono::seconds(1);

class pl_factory : public panda_link_factory {
public:
    pl_factory(
      ss::sharded<cluster::metadata_cache>* metadata_cache,
      cluster::controller* controller)
      : _metadata_cache(metadata_cache)
      , _controller(controller) {}

    ss::future<std::unique_ptr<panda_link>> create(
      std::vector<net::unresolved_address> source_broker_bootstrap_servers,
      std::vector<model::topic> mirrored_topics) override {
        co_return std::make_unique<panda_link>(
          std::move(source_broker_bootstrap_servers),
          std::move(mirrored_topics),
          transform::rpc::topic_metadata_cache::make_default(_metadata_cache),
          transform::rpc::topic_creator::make_default(_controller));
    }

private:
    ss::sharded<cluster::metadata_cache>* _metadata_cache;
    cluster::controller* _controller;
};

std::unique_ptr<kc> create_kafka_client(
  const std::vector<net::unresolved_address>& source_broker_bootstrap_servers) {
    kc_config cfg;
    cfg.brokers.set_value(source_broker_bootstrap_servers);
    return std::make_unique<kc>(
      config::to_yaml(cfg, config::redact_secrets::no));
}

struct topic_data {
    int32_t partition_count{-1};
    int16_t replication_factor{-1};
    cluster::topic_properties properties{};
};

ss::future<result<absl::flat_hash_map<model::topic, topic_data>>>
get_topic_configs(const model::panda_link_metadata& meta) {
    try {
        vlog(
          cllog.debug, "Attempting to get topic config for link {}", meta.name);
        auto client = create_kafka_client(meta.source_cluster_bootstrap_server);
        co_await client->connect();
        auto metadata_resp = co_await client->get_metadata();
        auto metadata_topics = std::move(metadata_resp.data.topics);
        const auto get_topic_data = [&metadata_topics](model::topic_view tp) {
            auto it = std::ranges::find_if(
              metadata_topics,
              [&tp](const auto& topic) { return topic.name == tp; });
            if (it == metadata_topics.end()) {
                throw kafka::client::topic_error(
                  tp, kafka::error_code::unknown_topic_or_partition);
            }
            return topic_data{
              .partition_count = static_cast<int32_t>(it->partitions.size()),
              .replication_factor = static_cast<int16_t>(
                it->partitions[0].replica_nodes.size()),
            };
        };
        const auto create_creatable_topic_config =
          [](
            model::topic_view topic,
            const topic_data& td,
            const kafka::describe_configs_result& configs) {
              kafka::creatable_topic ct;
              ct.name = topic;
              ct.num_partitions = td.partition_count;
              ct.replication_factor = td.replication_factor;
              ct.configs.reserve(configs.configs.size());
              for (const auto& config : configs.configs) {
                  ct.configs.emplace_back(kafka::createable_topic_config{
                    .name = config.name, .value = config.value});
              }
              return ct;
          };
        auto topics = meta.mirrored_topics;
        absl::flat_hash_map<model::topic, topic_data> configs;
        for (const auto& topic : topics) {
            vlog(cllog.trace, "Getting config for topic {}", topic);
            auto response = co_await client->describe_topic(
              topic, std::nullopt);
            vlog(cllog.trace, "Got config for topic {}: {}", topic, response);
            auto td = get_topic_data(topic);
            auto ct = create_creatable_topic_config(
              topic, td, response.data.results[0]);
            auto cluster_type = kafka::to_cluster_type(ct);
            configs.emplace(
              topic,
              topic_data{
                .partition_count = cluster_type.cfg.partition_count,
                .replication_factor = cluster_type.cfg.replication_factor,
                .properties = std::move(cluster_type.cfg.properties),
              });
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
  model::node_id self,
  ss::sharded<cluster::panda_link_frontend>* pl_frontend,
  std::unique_ptr<transform::rpc::topic_creator> topic_creator,
  ss::sharded<cluster::partition_manager>* partition_manager,
  ss::sharded<raft::group_manager>* group_manager,
  ss::sharded<cluster::metadata_cache>* metadata_cache,
  cluster::controller* controller)
  : _self(self)
  , _pl_frontend(pl_frontend)
  , _topic_creator(std::move(topic_creator))
  , _partition_manager(partition_manager)
  , _group_manager(group_manager)
  , _metadata_cache(metadata_cache)
  , _controller(controller) {}

service::~service() = default;

ss::future<> service::start() {
    _manager = std::make_unique<manager>(
      _self,
      std::make_unique<panda_link_registry_adapter>(&_pl_frontend->local()),
      std::make_unique<pl_factory>(_metadata_cache, _controller));

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

    for (const auto& [topic, topic_data] : cfgs) {
        auto ec = co_await _topic_creator->create_topic(
          model::topic_namespace{model::ns{model::kafka_ns_view}, topic},
          topic_data.partition_count,
          topic_data.replication_factor,
          topic_data.properties);
        if (ec != cluster::errc::success) {
            vlog(
              cllog.error,
              "failed to create topic {} for link {}: {}",
              topic,
              meta.name,
              cluster::make_error_code(ec).message());
            co_return cluster::make_error_code(ec);
        }
    }

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
    auto leadership_notif_id
      = _group_manager->local().register_leadership_notification(
        [this](
          raft::group_id group_id,
          model::term_id,
          std::optional<model::node_id> leader) {
            vlog(
              cllog.trace,
              "leadership_notification: group_id: {}, leader: {}",
              group_id,
              leader);
            auto partition = _partition_manager->local().partition_for(
              group_id);
            if (!partition) {
                vlog(
                  cllog.debug,
                  "got leadership notification for unknown partition: {}",
                  group_id);
                return;
            }
            vlog(cllog.trace, "ntp: {}", partition->ntp());
            bool node_is_leader = leader.has_value() && leader == _self;
            if (!node_is_leader) {
                _manager->on_leadership_change(
                  partition->ntp(), ntp_leader::no);
                return;
            }
            ntp_leader is_leader = partition && partition->is_elected_leader()
                                     ? ntp_leader::yes
                                     : ntp_leader::no;
            _manager->on_leadership_change(partition->ntp(), is_leader);
        });
    _notification_cleanups.emplace_back([this, leadership_notif_id] {
        _group_manager->local().unregister_leadership_notification(
          leadership_notif_id);
    });
    auto unmanage_notification_id
      = _partition_manager->local().register_unmanage_notification(
        model::kafka_namespace, [this](model::topic_partition_view tp) {
            vlog(
              cllog.trace,
              "unmanage_notification: {}:{}",
              tp.topic,
              tp.partition);
            _manager->on_leadership_change(
              model::ntp(model::kafka_namespace, tp.topic, tp.partition),
              ntp_leader::no);
        });
    _notification_cleanups.emplace_back([this, unmanage_notification_id] {
        _partition_manager->local().unregister_unmanage_notification(
          unmanage_notification_id);
    });
    auto manage_notifications_id
      = _partition_manager->local().register_manage_notification(
        model::kafka_namespace,
        [this](const ss::lw_shared_ptr<cluster::partition>& p) {
            vlog(cllog.trace, "manage_notification: {}", p->ntp());
            ntp_leader is_leader = p->is_elected_leader() ? ntp_leader::yes
                                                          : ntp_leader::no;
            _manager->on_leadership_change(p->ntp(), is_leader);
        });
    _notification_cleanups.emplace_back([this, manage_notifications_id] {
        _partition_manager->local().unregister_manage_notification(
          manage_notifications_id);
    });
}

void service::unregister_notifications() { _notification_cleanups.clear(); }
} // namespace cluster_link
