// Copyright 2024 Redpanda Data, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

#include "cluster/fwd.h"
#include "cluster/types.h"
#include "kafka/data/partition_proxy.h"
#include "kafka/data/replicated_partition.h"
#include "kafka/protocol/errors.h"
#include "model/fundamental.h"
#include "model/metadata.h"
#include "model/namespace.h"
#include "model/record_batch_types.h"
#include "model/tests/random_batch.h"
#include "raft/replicate.h"
#include "redpanda/tests/fixture.h"
#include "storage/record_batch_builder.h"
#include "test_utils/async.h"
#include "test_utils/boost_fixture.h"

FIXTURE_TEST(test_replicated_partition_end_offset, redpanda_thread_fixture) {
    wait_for_controller_leadership().get();

    model::topic_namespace tp_ns(
      model::kafka_namespace, model::topic("test-topic"));

    add_topic(tp_ns).get();
    model::ntp ntp(tp_ns.ns, tp_ns.tp, model::partition_id(0));
    auto shard = app.shard_table.local().shard_for(ntp);

    tests::cooperative_spin_wait_with_timeout(10s, [this, shard, &ntp] {
        return app.partition_manager.invoke_on(
          *shard, [&ntp](cluster::partition_manager& pm) {
              auto p = pm.get(ntp);
              return p->is_leader();
          });
    }).get();

    app.partition_manager
      .invoke_on(
        *shard,
        [&ntp](cluster::partition_manager& pm) {
            auto p = pm.get(ntp);
            kafka::replicated_partition rp(p);
            auto p_info = rp.get_partition_info();
            /**
             * Since log is empty from Kafka client perspective (no data
             * batches), the end offset which is exclusive must be equal to 0
             */
            BOOST_REQUIRE_EQUAL(rp.log_end_offset(), model::offset{0});
            BOOST_REQUIRE_EQUAL(rp.high_watermark(), model::offset{0});

            storage::record_batch_builder builder(
              model::record_batch_type::version_fence, model::offset(0));
            builder.add_raw_kv(iobuf{}, iobuf{});
            builder.add_raw_kv(iobuf{}, iobuf{});
            builder.add_raw_kv(iobuf{}, iobuf{});

            // replicate a batch that is subjected to offset translation
            return p
              ->replicate(
                chunked_vector<model::record_batch>::single(
                  std::move(builder).build()),
                raft::replicate_options(raft::consistency_level::quorum_ack))
              .then([p, rp](result<cluster::kafka_result> rr) {
                  BOOST_REQUIRE(rr.has_value());
                  BOOST_REQUIRE_GT(p->dirty_offset(), model::offset{0});

                  BOOST_REQUIRE_EQUAL(rp.log_end_offset(), model::offset{0});
                  BOOST_REQUIRE_EQUAL(rp.high_watermark(), model::offset{0});
              });
        })
      .get();
}

FIXTURE_TEST(
  test_replicated_partition_prefix_truncate_above_hwm,
  redpanda_thread_fixture) {
    wait_for_controller_leadership().get();

    model::topic_namespace tp_ns(
      model::kafka_namespace, model::topic("test-topic"));

    add_topic(tp_ns).get();
    model::ntp ntp(tp_ns.ns, tp_ns.tp, model::partition_id(0));
    auto shard = app.shard_table.local().shard_for(ntp);

    tests::cooperative_spin_wait_with_timeout(10s, [this, shard, &ntp] {
        return app.partition_manager.invoke_on(
          *shard, [&ntp](cluster::partition_manager& pm) {
              auto p = pm.get(ntp);
              return p->is_leader();
          });
    }).get();

    // Replicate some data batches to have a non-zero HWM
    app.partition_manager
      .invoke_on(
        *shard,
        [&ntp](cluster::partition_manager& pm) {
            auto p = pm.get(ntp);
            return model::test::make_random_batches(model::offset(0), 5)
              .then([p](auto batches) {
                  return p
                    ->replicate(
                      chunked_vector<model::record_batch>(
                        std::from_range,
                        std::move(batches) | std::views::as_rvalue),
                      raft::replicate_options(
                        raft::consistency_level::quorum_ack))
                    .discard_result();
              });
        })
      .get();

    // Wait for the data to be committed
    tests::cooperative_spin_wait_with_timeout(10s, [this, shard, &ntp] {
        return app.partition_manager.invoke_on(
          *shard, [&ntp](cluster::partition_manager& pm) {
              auto p = pm.get(ntp);
              kafka::replicated_partition rp(p);
              return rp.high_watermark() >= model::offset{5};
          });
    }).get();

    app.partition_manager
      .invoke_on(
        *shard,
        [&ntp](cluster::partition_manager& pm) {
            auto p = pm.get(ntp);
            kafka::replicated_partition rp(p);

            auto hwm = rp.high_watermark();
            BOOST_REQUIRE_GE(hwm, model::offset{5});

            // An offset above the HWM
            auto offset_above_hwm = hwm + model::offset{10};
            auto deadline = ss::lowres_clock::now() + std::chrono::seconds(5);

            // Test 1: By default, truncating above HWM should fail with
            // offset_out_of_range
            return rp.prefix_truncate(offset_above_hwm, deadline)
              .then(
                [rp, offset_above_hwm, deadline](auto result_default) mutable {
                    BOOST_REQUIRE_EQUAL(
                      result_default, kafka::error_code::offset_out_of_range);

                    // Test 2: With allow_truncate_above_hwm::no, should also
                    // fail
                    return rp.prefix_truncate(
                      offset_above_hwm,
                      deadline,
                      kafka::allow_truncate_above_hwm::no);
                })
              .then([rp, offset_above_hwm, deadline](auto result_no) mutable {
                  BOOST_REQUIRE_EQUAL(
                    result_no, kafka::error_code::offset_out_of_range);

                  // Test 3: With allow_truncate_above_hwm::yes, should
                  // succeed
                  return rp.prefix_truncate(
                    offset_above_hwm,
                    deadline,
                    kafka::allow_truncate_above_hwm::yes);
              })
              .then([rp, offset_above_hwm](auto result_yes) {
                  // The truncation should succeed (not return
                  // offset_out_of_range) This is the key test: with
                  // allow_truncate_above_hwm::yes, the HWM check is bypassed.
                  BOOST_REQUIRE_EQUAL(result_yes, kafka::error_code::none);
                  auto start_offset = rp.start_offset();
                  BOOST_REQUIRE_EQUAL(start_offset, offset_above_hwm);
              });
        })
      .get();
}
