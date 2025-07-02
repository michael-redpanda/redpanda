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

#include "cluster_link/link.h"

#include "cluster_link/logger.h"

namespace cluster_link {

using kafka::data::rpc::partition_leader_cache;
using kafka::data::rpc::partition_manager;

link::link(
  model::metadata config,
  partition_leader_cache* partition_leader_cache,
  partition_manager* partition_manager)
  : _config(std::move(config))
  , _partition_leader_cache(partition_leader_cache)
  , _partition_manager(partition_manager) {}

ss::future<> link::start() {
    vlog(
      cllog.info, "Starting cluster link {} ({})", _config.name, _config.uuid);
    return ss::now();
}

ss::future<> link::stop() {
    vlog(
      cllog.info, "Stopping cluster link {} ({})", _config.name, _config.uuid);
    return ss::now();
}

ss::future<result<void>> link::register_task(std::unique_ptr<task> t) {
    vlog(
      cllog.debug,
      "Registering task {} for cluster link {} ({})",
      t->name(),
      _config.name,
      _config.uuid);
    if (_tasks.contains(t->name())) {
        auto msg = ssx::sformat(
          "Task named '{}' already exists for link {}",
          t->name(),
          _config.name);
        vlog(cllog.warn, "{}", msg);
        co_return err_info(
          errc::task_already_registered_on_link, std::move(msg));
    }

    auto name = t->name();
    _tasks.emplace(std::move(name), std::move(t));
    co_return outcome::success();
}

void link::update_config(model::metadata config) {
    vlog(
      cllog.debug,
      "Updating cluster link {} ({}): {}",
      _config.name,
      _config.uuid,
      config);
    _config = std::move(config);

    for (auto& [_, t] : _tasks) {
        t->update_config(_config);
    }
}

const model::metadata& link::config() const { return _config; }

bool link::task_is_registered(const ss::sstring& name) const noexcept {
    return _tasks.contains(name);
}
} // namespace cluster_link
