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

#include "cluster_link/model/types.h"
#include "cluster_link/task.h"
#include "kafka/data/rpc/deps.h"

namespace cluster_link {
/**
 * @brief The link class represents a link between two clusters
 */
class link {
public:
    explicit link(
      model::metadata config,
      kafka::data::rpc::partition_leader_cache* partition_leader_cache,
      kafka::data::rpc::partition_manager* partition_manager);
    link(const link&) = delete;
    link(link&&) = delete;
    link& operator=(const link&) = delete;
    link& operator=(link&&) = delete;
    virtual ~link() = default;

    virtual ss::future<> start();
    virtual ss::future<> stop();

    ss::future<result<void>> register_task(std::unique_ptr<task>);

    void update_config(model::metadata);

    const model::metadata& config() const;

    bool task_is_registered(const ss::sstring&) const noexcept;

private:
    chunked_hash_map<ss::sstring, std::unique_ptr<task>> _tasks;
    model::metadata _config;
    kafka::data::rpc::partition_leader_cache* _partition_leader_cache;
    kafka::data::rpc::partition_manager* _partition_manager;
};
} // namespace cluster_link
