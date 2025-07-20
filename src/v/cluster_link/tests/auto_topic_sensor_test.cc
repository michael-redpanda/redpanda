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

#include "cluster_link/auto_topic_sensor.h"
#include "cluster_link/tests/deps.h"
#include "test_utils/test.h"

#include <algorithm>

using namespace std::chrono_literals;

namespace cluster_link::tests {

class auto_topic_sensor_test : public seastar_test {
public:
    static constexpr auto task_reconciler_interval = 1s;
    ss::future<> SetUpAsync() override {
        _clmtf = std::make_unique<cluster_link_manager_test_fixture>(self());
        co_await _clmtf->wire_up_and_start(
          std::make_unique<test_link_factory>(task_reconciler_interval));

        co_await _clmtf->get_manager().invoke_on_all([](manager& m) {
            return m.register_task_factory<auto_topic_sensor_factory>();
        });

        fixture()->elect_leader(::model::controller_ntp, self(), std::nullopt);
    }

    ss::future<> TearDownAsync() override {
        co_await _clmtf->reset();
        _clmtf.reset();
    }

    cluster_link_manager_test_fixture* fixture() { return _clmtf.get(); }

    ::model::node_id self() { return ::model::node_id(0); }

private:
    std::unique_ptr<cluster_link_manager_test_fixture> _clmtf;
};

TEST_F_CORO(auto_topic_sensor_test, create_auto_topic_sensor_task) {
    co_await fixture()->upsert_link(get_default_metadata());

    auto report = co_await fixture()->await_status_report(
      5s, 100ms, [](const model::cluster_link_task_status_report& report) {
          auto link_it = report.link_reports.find(model::name_t("test_link"));
          if (link_it == report.link_reports.end()) {
              return false;
          }
          auto task_it = link_it->second.task_status_reports.find(
            auto_topic_sensor::task_name);
          if (task_it == link_it->second.task_status_reports.end()) {
              return false;
          }

          return true;
      });

    ASSERT_TRUE_CORO(report.has_value()) << "Never received a task report";

    auto& task_report = report.value()
                          .link_reports.at(model::name_t("test_link"))
                          .task_status_reports.at(auto_topic_sensor::task_name);
    EXPECT_EQ(task_report.task_state, model::task_state::active);
}
} // namespace cluster_link::tests
