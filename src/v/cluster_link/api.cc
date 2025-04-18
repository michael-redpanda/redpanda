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

#include "cluster_link/api.h"

#include <seastar/util/later.hh>

namespace cluster_link {
ss::future<> service::start() {
    // Start the service
    return ss::now();
}

ss::future<> service::stop() { return ss::now(); }
} // namespace cluster_link
