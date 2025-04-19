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
#include "model/panda_link.h"
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

    using notification_id = panda_link_table::notification_id;
    using notification_callback = panda_link_table::notification_callback;

    struct mutation_result {
        errc ec;
    };

    ss::future<errc> upsert_panda_link(
      model::panda_link_metadata, model::timeout_clock::time_point);

    ss::future<mutation_result> delete_panda_link(
      model::panda_link_name, model::timeout_clock::time_point);

    std::optional<model::panda_link_metadata>
    lookup_panda_link(const model::panda_link_name&) const;
    std::optional<model::panda_link_metadata>
      lookup_panda_link(model::panda_link_id) const;
    notification_id register_for_updates(notification_callback);
    void unregister_for_updates(notification_id);

private:
    ss::future<mutation_result>
      do_mutation(panda_link_cmd, model::timeout_clock::time_point);

    ss::future<mutation_result> dispatch_mutation_to_remote(
      model::node_id, panda_link_cmd, model::timeout_clock::duration);

    ss::future<mutation_result>
      do_local_mutation(panda_link_cmd, model::timeout_clock::time_point);

    errc validate_mutation(const panda_link_cmd&);

public:
    class validator {
    public:
        explicit validator(panda_link_table*);

        errc validate_mutation(const panda_link_cmd&);

    private:
        panda_link_table* _table;
    };

private:
    model::node_id _self;
    partition_leaders_table* _leaders;
    rpc::connection_cache* _connections;
    panda_link_table* _table;
    ss::abort_source* _as;

    controller_stm* _controller;

    mutex _mu{"panda_link_frontend::mu"};
};
} // namespace cluster
