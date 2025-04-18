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

#pragma once

#include "base/seastarx.h"
#include "cluster/commands.h"
#include "cluster/fwd.h"
#include "cluster/panda_link_table.h"
#include "rpc/connection_cache.h"

#include <seastar/core/sharded.hh>

namespace cluster {
class panda_link_frontend
  : public ss::peering_sharded_service<panda_link_frontend> {
private:
    using panda_link_cmd
      = std::variant<panda_link_update_cmd, panda_link_remove_cmd>;

public:
    panda_link_frontend(
      model::node_id,
      partition_leaders_table*,
      panda_link_table*,
      controller_stm*,
      rpc::connection_cache*,
      ss::abort_source*);

private:
    model::node_id _self;
    partition_leaders_table* _leaders;
    rpc::connection_cache* _connections;
    panda_link_table* _table;
    ss::abort_source* _as;

    controller_stm* _controller;
};
} // namespace cluster
