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
#include "base/outcome.h"
#include "kafka/protocol/describe_configs.h"

namespace cluster_link {
class source_cluster_client {
public:
    source_cluster_client() = default;
    source_cluster_client(const source_cluster_client&) = delete;
    source_cluster_client& operator=(const source_cluster_client&) = delete;
    source_cluster_client(source_cluster_client&&) = default;
    source_cluster_client& operator=(source_cluster_client&&) = default;
    virtual ~source_cluster_client() = default;

    /// \brief Describe the topic configs for the given topic.
    /// \param topic The topic to describe.
    /// \return A future that will be ready with the result of the describe
    ///         configs request.
    virtual ss::future<
      result<kafka::describe_configs_resource_result, std::error_code>>
    describe_topic_configs(model::topic_view topic) = 0;
};
class panda_link {};
} // namespace cluster_link
