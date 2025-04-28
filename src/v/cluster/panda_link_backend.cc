/*
 * Copyright 2025 Redpanda Data, Inc.
 *
 * Licensed as a Redpanda Enterprise file under the Redpanda Community
 * License (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://github.com/redpanda-data/redpanda/blob/master/licenses/rcl.md
 */

#include "cluster/panda_link_backend.h"

#include "cluster/commands.h"
#include "cluster/errc.h"
#include "cluster/logger.h"
#include "cluster/panda_link_table.h"

#include <seastar/util/variant_utils.hh>

#include <variant>

namespace cluster {
panda_link_backend::panda_link_backend(ss::sharded<panda_link_table>* table)
  : _panda_link_table(table) {}

bool panda_link_backend::is_batch_applicable(const model::record_batch& b) {
    return b.header().type == model::record_batch_type::panda_link_update;
}

ss::future<std::error_code>
panda_link_backend::apply_update(model::record_batch b) {
    auto offset = b.base_offset();
    auto cmd = co_await cluster::deserialize(std::move(b), accepted_commands);
    auto ec = co_await _panda_link_table->map_reduce0(
      [&cmd, offset](panda_link_table& table) {
          return ss::visit(
            cmd,
            [&table, offset](const panda_link_update_cmd& update) {
                auto existing_id = table.find_id_by_name(update.value.name);
                return table.upsert_link(
                  existing_id.value_or(model::panda_link_id{offset}),
                  update.value);
            },
            [&table](const panda_link_remove_cmd& remove) {
                table.remove_link(remove.key);
                return make_error_code(errc::success);
            });
      },
      std::error_code{},
      [](std::error_code ec, std::error_code update) {
          if (update && !ec) {
              return update;
          }
          return ec;
      });

    if (ec) {
        co_await ss::visit(
          cmd,
          [this, ec](const panda_link_update_cmd& update) {
              vlog(
                clusterlog.warn,
                "Failed to apply update command for link {}: {}... removing "
                "link",
                update.value.name,
                ec);
              return _panda_link_table->invoke_on_all(
                [&update](panda_link_table& table) {
                    table.remove_link(update.value.name);
                });
          },
          [ec](const panda_link_remove_cmd& remove) {
              vlog(
                clusterlog.warn,
                "Failed to remove link {}: {}",
                remove.key,
                ec);
              return ss::now();
          });
    }

    co_return ec;
}
} // namespace cluster
