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

#include "cluster_link/auto_topic_sensor.h"

#include "cluster_link/link.h"

#include <fmt/ranges.h>

namespace cluster_link {
auto_topic_sensor::auto_topic_sensor(link* link, const model::metadata& config)
  : task(
      link,
      config.state.topic_metadata_mirroring_cfg.task_interval,
      auto_topic_sensor::task_name) {}

task::is_locked_to_controller
auto_topic_sensor::locked_to_controller() const noexcept {
    return is_locked_to_controller::yes;
}

void auto_topic_sensor::update_config(const model::metadata& config) {
    set_run_interval(config.state.topic_metadata_mirroring_cfg.task_interval);
}

ss::future<> auto_topic_sensor::run_impl() {
    // Implementation of the auto topic sensor logic
    // This is where the task will check for topics that need to be created
    // and create them if necessary.
    co_return;
}

std::string_view auto_topic_sensor_factory::created_task_name() const noexcept {
    return auto_topic_sensor::task_name;
}

std::unique_ptr<task> auto_topic_sensor_factory::create_task(link* link) {
    return std::make_unique<auto_topic_sensor>(link, link->get_config());
}
} // namespace cluster_link
