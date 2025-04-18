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

#include "cluster_link/panda_link_manager.h"

namespace cluster_link {

ss::future<void> manager::start() {
    // Start the client
    return ss::now();
}

ss::future<void> manager::stop() {
    // Stop the client
    return ss::now();
}
} // namespace cluster_link
