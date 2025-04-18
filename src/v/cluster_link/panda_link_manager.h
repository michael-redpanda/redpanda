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

namespace cluster_link {

class panda_link_factory {
public:
    panda_link_factory() = default;
    panda_link_factory(const panda_link_factory&) = delete;
    panda_link_factory& operator=(const panda_link_factory&) = delete;
    panda_link_factory(panda_link_factory&&) = default;
    panda_link_factory& operator=(panda_link_factory&&) = default;
    virtual ~panda_link_factory() = default;

    virtual ss::future<std::unique_ptr<panda_link>>
    create(ss::sstring broker_address) = 0;

private:
};

class manager {
public:
    manager() = default;
    manager(const manager&) = delete;
    manager& operator=(const manager&) = delete;
    manager(manager&&) = default;
    manager& operator=(manager&&) = default;
    virtual ~manager() = default;

    ss::future<void> start();
    ss::future<void> stop();

private:
    std::unique_ptr<panda_link_factory> _panda_link_factory;
};
} // namespace cluster_link
