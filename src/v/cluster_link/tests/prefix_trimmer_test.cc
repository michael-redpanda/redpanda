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

#include "cluster_link/prefix_trimmer.h"
#include "cluster_link/source_topic_syncer.h"
#include "cluster_link/tests/deps.h"
#include "test_utils/async.h"
#include "test_utils/test.h"

namespace cluster_link::tests {

using model::filter_pattern_type;
using model::filter_type;
using model::resource_name_filter_pattern;

namespace {
model::metadata get_default_metadata() {
    model::link_state link_state;
    model::metadata metadata{
      .name = model::name_t("test_link"),
      .uuid = model::uuid_t(::uuid_t::create()),
      .connection = model::
        connection_config{.bootstrap_servers = {net::unresolved_address("localhost", 9092)}},
      .state = std::move(link_state)};
    metadata.configuration.topic_metadata_mirroring_cfg.task_interval = 1s;
    metadata.configuration.topic_metadata_mirroring_cfg.topic_name_filters
      .emplace_back(
        resource_name_filter_pattern{
          .pattern_type = filter_pattern_type::literal,
          .filter = filter_type::include,
          .pattern = resource_name_filter_pattern::wildcard});
    metadata.configuration.partition_prefix_trimming_cfg.task_interval = 1s;
    return metadata;
}
} // namespace

class prefix_trimmer_test : public seastar_test {
public:
    static constexpr auto task_reconciler_interval = 1s;

    ss::future<> SetUpAsync() override {
        _clmtf = std::make_unique<cluster_link_manager_test_fixture>(self());
        co_await _clmtf->wire_up_and_start(
          std::make_unique<test_link_factory>(task_reconciler_interval));

        co_await _clmtf->get_manager().invoke_on_all([](manager& m) {
            return m.register_task_factory<source_topic_syncer_factory>();
        });
        co_await _clmtf->get_manager().invoke_on_all([](manager& m) {
            return m.register_task_factory<prefix_trimmer_factory>();
        });

        fixture().elect_leader(::model::controller_ntp, self(), std::nullopt);
    }

    ss::future<> TearDownAsync() override {
        co_await _clmtf->reset();
        _clmtf.reset();
    }

    ::model::node_id self() { return ::model::node_id(0); }

    cluster_link_manager_test_fixture& fixture() { return *_clmtf; }

private:
    std::unique_ptr<cluster_link_manager_test_fixture> _clmtf;
};

TEST_F_CORO(prefix_trimmer_test, test_prefix_trimmer) {
    co_await fixture().upsert_link(get_default_metadata());

    fixture().get_cluster_mock().add_topic(
      ::model::topic("test_topic"),
      3,
      3,
      kafka::topic_authorized_operations(0x508));

    // Allow auto topic sensor to run
    RPTEST_REQUIRE_EVENTUALLY_CORO(5s, [this] {
        auto link_metadata = fixture().find_link_by_name(
          model::name_t("test_link"));
        auto& mirror_topics = link_metadata->get().state.mirror_topics;
        auto mirror_topic_it = mirror_topics.find(::model::topic("test_topic"));
        return mirror_topic_it != mirror_topics.end();
    });

    // Ensure that the topic has been created
    RPTEST_REQUIRE_EVENTUALLY_CORO(5s, [this] {
        auto& tmc = fixture().topic_metadata_cache();
        return tmc
                 .get_partition_offsets(
                   ::model::ntp(
                     ::model::kafka_namespace, ::model::topic("test_topic"), 0))
                 .has_value()
               && tmc
                    .get_partition_offsets(
                      ::model::ntp(
                        ::model::kafka_namespace,
                        ::model::topic("test_topic"),
                        1))
                    .has_value()
               && tmc
                    .get_partition_offsets(
                      ::model::ntp(
                        ::model::kafka_namespace,
                        ::model::topic("test_topic"),
                        2))
                    .has_value();
    });

    // Now set the start offset on the source partitions
    for (auto i = 0; i < 3; ++i) {
        fixture().get_cluster_mock().set_partition_offsets(
          {::model::topic{"test_topic"}, ::model::partition_id{i}},
          std::nullopt,
          std::nullopt,
          ::model::offset{(i + 1) * 10});
    }

    // Allow for the prefix trimmer to run and then ensure the start offsets are
    // still 0
    co_await ss::sleep(3s);

    auto& tmc = fixture().topic_metadata_cache();
    for (auto i = 0; i < 3; ++i) {
        auto offsets = tmc.get_partition_offsets(
          ::model::ntp(
            ::model::kafka_namespace, ::model::topic("test_topic"), i));
        ASSERT_TRUE_CORO(offsets.has_value());
        EXPECT_EQ(offsets->log_start_offset, ::model::offset(0));
    }

    // Before updating the start offsets, inject an error
    fixture().kafka_rpc_client_service().inserted_get_partition_offsets_error
      = cluster::errc::timeout;

    // now update the log start offset on the mirror partitions to 10
    for (auto i = 0; i < 3; ++i) {
        fixture().set_partition_hwm(
          {::model::topic{"test_topic"}, ::model::partition_id{i}},
          kafka::offset(10));
    }

    // now we should see partition 0 be at starting offset 10, but the others
    // should be at zero
    RPTEST_REQUIRE_EVENTUALLY_CORO(5s, [&tmc] {
        auto offsets = tmc.get_partition_offsets(
          ::model::ntp(
            ::model::kafka_namespace, ::model::topic("test_topic"), 0));
        if (
          !offsets.has_value()
          || offsets->log_start_offset != ::model::offset(10)) {
            return false;
        }
        offsets = tmc.get_partition_offsets(
          ::model::ntp(
            ::model::kafka_namespace, ::model::topic("test_topic"), 1));
        if (
          !offsets.has_value()
          || offsets->log_start_offset != ::model::offset(0)) {
            return false;
        }
        offsets = tmc.get_partition_offsets(
          ::model::ntp(
            ::model::kafka_namespace, ::model::topic("test_topic"), 2));
        if (
          !offsets.has_value()
          || offsets->log_start_offset != ::model::offset(0)) {
            return false;
        }
        return true;
    });
}
} // namespace cluster_link::tests
