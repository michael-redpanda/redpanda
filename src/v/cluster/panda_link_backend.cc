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

#include "cluster/panda_link_backend.h"

#include "cluster/controller_snapshot.h"
#include "cluster/panda_link_table.h"

namespace cluster {
panda_link_backend::panda_link_backend(ss::sharded<panda_link_table>* t)
  : _table(t) {}

bool panda_link_backend::is_batch_applicable(const model::record_batch& b) {
    return b.header().type == model::record_batch_type::panda_link_update;
}

ss::future<std::error_code>
panda_link_backend::apply_update(model::record_batch b) {
    auto offset = b.base_offset();
    auto cmd = co_await cluster::deserialize(std::move(b), accepted_commands);
    co_await _table->invoke_on_all([&cmd, offset](panda_link_table& table) {
        return ss::visit(
          cmd,
          [&table, offset](panda_link_update_cmd update) {
              auto existing_id = table.find_id_by_name(update.value.name);
              table.upsert_link(
                existing_id.value_or(model::panda_link_id{offset}),
                update.value);
          },
          [&table](const panda_link_remove_cmd& removal) {
              table.remove_link(removal.key);
          });
    });

    co_return errc::success;
}

ss::future<>
panda_link_backend::fill_snapshot(controller_snapshot& snap) const {
    snap.panda_links.links = _table->local().all_links();
    return ss::now();
}

ss::future<> panda_link_backend::apply_snapshot(
  model::offset, const controller_snapshot& snap) {
    return _table->invoke_on_all(
      [&snap](auto& table) { table.reset_links(snap.panda_links.links); });
}
} // namespace cluster
