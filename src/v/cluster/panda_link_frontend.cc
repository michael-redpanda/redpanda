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

#include "cluster/panda_link_frontend.h"

namespace cluster {
panda_link_frontend::panda_link_frontend(
  model::node_id self,
  partition_leaders_table* leaders,
  panda_link_table* table,
  controller_stm* controller,
  rpc::connection_cache* connections,
  ss::abort_source* as)
  : _self(self)
  , _leaders(leaders)
  , _connections(connections)
  , _table(table)
  , _as(as)
  , _controller(controller) {}
} // namespace cluster
