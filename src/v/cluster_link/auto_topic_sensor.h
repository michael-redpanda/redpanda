/**
 * Copyright 2025 Redpanda Data, Inc.
 *
 * Licensed as a Redpanda Enterprise file under the Redpanda Community
 * License (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://github.com/redpanda-data/redpanda/blob/dev/licenses/rcl.md
 *
 */

#pragma once

#include "cluster_link/task.h"

namespace cluster_link {
class auto_topic_sensor : public task {
public:
    static constexpr auto task_name = "Auto Topic Creator";
    auto_topic_sensor(link* link, const model::metadata& config);
    auto_topic_sensor(const auto_topic_sensor&) = delete;
    auto_topic_sensor(auto_topic_sensor&&) = delete;
    auto_topic_sensor& operator=(const auto_topic_sensor&) = delete;
    auto_topic_sensor& operator=(auto_topic_sensor&&) = delete;
    ~auto_topic_sensor() override = default;

    is_locked_to_controller locked_to_controller() const noexcept override;

    void update_config(const model::metadata& config) override;

protected:
    ss::future<> run_impl() override;
};

class auto_topic_sensor_factory : public task_factory {
public:
    /// Returns the name of the task that this factory creates
    std::string_view created_task_name() const noexcept override;

    /// Creates a new task through the factory.  Provides the owning link
    std::unique_ptr<task> create_task(link* link) override;
};
} // namespace cluster_link
