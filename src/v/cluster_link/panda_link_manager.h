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

#include "cluster_link/panda_link.h"
#include "model/panda_link.h"
#include "ssx/work_queue.h"

namespace cluster_link {

class panda_link_registry {
public:
    panda_link_registry() = default;
    panda_link_registry(const panda_link_registry&) = delete;
    panda_link_registry& operator=(const panda_link_registry&) = delete;
    panda_link_registry(panda_link_registry&&) = default;
    panda_link_registry& operator=(panda_link_registry&&) = default;
    virtual ~panda_link_registry() = default;

    virtual std::optional<model::panda_link_metadata>
      lookup_by_id(model::panda_link_id) const = 0;
};

class panda_link_factory {
public:
    panda_link_factory() = default;
    panda_link_factory(const panda_link_factory&) = delete;
    panda_link_factory& operator=(const panda_link_factory&) = delete;
    panda_link_factory(panda_link_factory&&) = default;
    panda_link_factory& operator=(panda_link_factory&&) = default;
    virtual ~panda_link_factory() = default;

    virtual ss::future<std::unique_ptr<panda_link>> create() = 0;
};

class manager {
public:
    manager(
      model::node_id,
      std::unique_ptr<panda_link_registry>,
      std::unique_ptr<panda_link_factory>);
    manager(const manager&) = delete;
    manager& operator=(const manager&) = delete;
    manager(manager&&) = delete;
    manager& operator=(manager&&) = delete;
    virtual ~manager() = default;

    ss::future<void> start();
    ss::future<void> stop();

    void on_link_change(model::panda_link_id);

private:
    ss::future<> handle_link_change(model::panda_link_id);

private:
    model::node_id _self;
    ssx::work_queue _queue;
    std::unique_ptr<panda_link_registry> _registry;
    std::unique_ptr<panda_link_factory> _factory;
};
} // namespace cluster_link
