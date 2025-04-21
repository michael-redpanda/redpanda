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
#include "cluster/fwd.h"
#include "cluster_link/fwd.h"
#include "model/panda_link.h"
#include "raft/group_manager.h"
#include "transform/rpc/deps.h"

#include <seastar/core/gate.hh>
#include <seastar/core/sharded.hh>
#include <seastar/util/defer.hh>

namespace cluster_link {
class service : public ss::peering_sharded_service<service> {
public:
    service(
      model::node_id self,
      ss::sharded<cluster::panda_link_frontend>* pl_frontend,
      std::unique_ptr<transform::rpc::topic_creator> topic_creator,
      ss::sharded<cluster::partition_manager>* partition_manager,
      ss::sharded<raft::group_manager>* group_manager);
    service(const service&) = delete;
    service& operator=(const service&) = delete;
    service(service&&) = delete;
    service& operator=(service&&) = delete;
    ~service();

    ss::future<> start();
    ss::future<> stop();

    ss::future<std::error_code> create_link(model::panda_link_metadata);

private:
    void register_notifications();
    void unregister_notifications();

private:
    ss::gate _gate;
    model::node_id _self;
    ss::sharded<cluster::panda_link_frontend>* _pl_frontend;
    std::unique_ptr<transform::rpc::topic_creator> _topic_creator;
    ss::sharded<cluster::partition_manager>* _partition_manager;
    ss::sharded<raft::group_manager>* _group_manager;
    std::unique_ptr<manager> _manager;
    std::vector<ss::deferred_action<ss::noncopyable_function<void()>>>
      _notification_cleanups;
};
} // namespace cluster_link
