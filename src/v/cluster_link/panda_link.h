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
#include "kafka/client/client.h"
#include "kafka/client/configuration.h"
#include "utils/unresolved_address.h"

#include <seastar/core/future.hh>
#include <seastar/core/sstring.hh>

namespace cluster_link {
class panda_link {
public:
    explicit panda_link(
      std::vector<net::unresolved_address> _source_broker_bootstrap_servers);
    panda_link(const panda_link&) = delete;
    panda_link& operator=(const panda_link&) = delete;
    panda_link(panda_link&&) = delete;
    panda_link& operator=(panda_link&&) = delete;

    virtual ~panda_link() = default;

    virtual ss::future<> start();
    virtual ss::future<> stop();

private:
    static kafka::client::configuration
    create_kafka_client_config(const std::vector<net::unresolved_address>&
                                 source_broker_bootstrap_servers);

private:
    std::vector<net::unresolved_address> _source_broker_bootstrap_servers;
    kafka::client::configuration _kc_config;
    std::unique_ptr<kafka::client::client> _client;
};
} // namespace cluster_link
