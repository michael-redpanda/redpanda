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

#include <seastar/core/sharded.hh>

namespace cluster_link {
class service : public ss::peering_sharded_service<service> {
public:
    service() = default;
    service(const service&) = delete;
    service& operator=(const service&) = delete;
    service(service&&) = delete;
    service& operator=(service&&) = delete;
    virtual ~service() = default;

    ss::future<> start();
    ss::future<> stop();

private:
};
} // namespace cluster_link
