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

#include <seastar/core/future.hh>
#include <seastar/core/sstring.hh>

namespace cluster_link {
class panda_link {
public:
    explicit panda_link(ss::sstring _source_broker_bootstrap_server);
    panda_link(const panda_link&) = delete;
    panda_link& operator=(const panda_link&) = delete;
    panda_link(panda_link&&) = default;
    panda_link& operator=(panda_link&&) = default;

    virtual ~panda_link() = default;

    virtual ss::future<> start();
    virtual ss::future<> stop();

private:
    ss::sstring _source_broker_bootstrap_server;
};
} // namespace cluster_link
