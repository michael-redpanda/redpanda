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

namespace cluster_link {

manager::manager(
  model::node_id self,
  std::unique_ptr<panda_link_registry> registry,
  ss::scheduling_group sg)
  : _self(self)
  , _queue(
      sg,
      [](const std::exception_ptr& ex) {
          vlog(cllog.error, "unexpected panda link manager error: {}", ex);
      })
  , _registry(std::move(registry)) {}

ss::future<void> manager::start() {
    // Start the client
    return ss::now();
}

ss::future<void> manager::stop() {
    vlog(cllog.info, , "Stopping panda link manager");
    co_await _queue.shutdown();
    vlog(cllog.info, "Stopped panda link manager");
}

void manager::on_link_change(model::panda_link_id id) {
    _queue.submit([this, id] { return handle_link_change(id); });
}

ss::future<> manager::handle_link_change(model::panda_link_id id) {
    vlog(cllog.trace, "handling link change for id {}", id);

    auto meta = _registry->lookup_by_id(id);
    if (!meta) {
        vlog(cllog.debug, "Detected link going down for {}", id);
        co_return;
    }

    vlog(cllog.debug, "Change/addition of link {}: {}", id, meta->name());
    co_return;
}
} // namespace cluster_link
