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

#include <seastar/core/sharded.hh>

namespace cluster {
class panda_link_backend {
public:
    explicit panda_link_backend(ss::sharded<panda_link_table>*);

    ss::future<std::error_code> apply_update(model::record_batch);
    bool is_batch_applicable(const model::record_batch&);

    ss::future<> fill_snapshot(controller_snapshot&) const;
    ss::future<> apply_snapshot(model::offset, const controller_snapshot&);

private:
    static constexpr auto accepted_commands
      = make_commands_list<panda_link_update_cmd, panda_link_remove_cmd>();

    ss::sharded<panda_link_table>* _table;
};
} // namespace cluster
