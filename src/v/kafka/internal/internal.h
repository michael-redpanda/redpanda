/*
 * Copyright 2023 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#pragma once

#include "cluster/metadata_cache.h"
#include "cluster/partition_manager.h"
#include "cluster/topics_frontend.h"
#include "kafka/protocol/types.h"
#include "seastarx.h"

#include <seastar/core/future.hh>
#include <seastar/core/sharded.hh>

namespace kafka::internal {
class internal final : public ss::peering_sharded_service<internal> {
public:
    internal(
      ss::sharded<cluster::metadata_cache>&,
      ss::sharded<cluster::topics_frontend>&,
      ss::sharded<cluster::partition_manager>&) noexcept;

    ~internal() noexcept = default;
    internal(const internal&) = delete;
    internal& operator=(const internal&) = delete;
    internal(internal&&) noexcept = delete;
    internal& operator=(internal&&) noexcept = delete;

    cluster::metadata_cache& metadata_cache() {
        return _metadata_cache.local();
    }

    cluster::topics_frontend& topics_frontend() {
        return _topics_frontend.local();
    }

    ss::sharded<cluster::partition_manager> & partition_manager() {
        return _partition_manager;
    }

private:
    ss::sharded<cluster::metadata_cache>& _metadata_cache;
    ss::sharded<cluster::topics_frontend>& _topics_frontend;
    ss::sharded<cluster::partition_manager>& _partition_manager;
};
} // namespace kafka::internal
