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

#include "cluster/panda_link_frontend.h"
#include "cluster_link/logger.h"
#include "cluster_link/panda_link_manager.h"

#include <seastar/util/later.hh>

namespace cluster_link {
namespace {
constexpr auto metadata_timeout = std::chrono::seconds(1);
}

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
      std::make_unique<panda_link_registry_adapter>(&_pl_frontend->local()));

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

    meta.uuid = model::panda_link_id{uuid_t::create()};

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
