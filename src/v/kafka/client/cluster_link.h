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

#include "kafka/client/cluster.h"
#include "kafka/client/configuration.h"
#include "utils/prefix_logger.h"

namespace kafka::client {
class cluster_link {
public:
    explicit cluster_link(const client_configuration& config);

    /// Connects to all brokers
    ss::future<> connect();
    /// Disconnects from all brokers
    ss::future<> stop() noexcept;

private:
    prefix_logger& logger();

private:
    prefix_logger _logger;
    cluster _cluster;

    bool _is_started{false};
    ss::abort_source _as;
};
} // namespace kafka::client
