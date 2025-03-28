# Copyright 2025 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

import time

from functools import partial
from typing import List, Optional

from ducktape.cluster.cluster import ClusterNode
from ducktape.mark import parametrize
from ducktape.utils.util import wait_until

from rptest.clients.default import DefaultClient
from rptest.clients.rpk import RpkException, RpkTool
from rptest.clients.types import TopicSpec

from rptest.services.admin import Admin
from rptest.services.cluster import cluster
from rptest.services.consumer_swarm import ConsumerSwarm
from rptest.services.redpanda import LoggingConfig
from rptest.services.redpanda_installer import RedpandaVersion, RedpandaVersionTriple
from rptest.services.verifiable_producer import VerifiableProducer

from rptest.tests.redpanda_test import RedpandaTest


class ConsumerGroupReproTest(RedpandaTest):
    def __init__(self, test_ctx, *args, **kwargs):
        super(ConsumerGroupReproTest, self).__init__(
            test_ctx,
            num_brokers=3,
            *args,
            extra_rp_conf={
                "default_topic_replications": 3,
                "log_compaction_interval_ms": 1000,
                "group_topic_partitions":
                1,  # Force CO to have a single partition
                "log_segment_size":
                8388608,  # sets log segment size for CO topic
            },
            log_config=LoggingConfig('info', logger_levels={'kafka': 'trace'}),
            **kwargs)
        self._client = DefaultClient(self.redpanda)
        self._topics: List[TopicSpec] = []
        self._cg_name = "test-cg-1"
        self._rpk = RpkTool(self.redpanda)
        self._admin = Admin(self.redpanda)
        self.installer = self.redpanda._installer
        self.cur_version = (23, 1, 1)
        self.final_version = (24, 3, 9)

    def increment_version(
            self, version: RedpandaVersionTriple) -> RedpandaVersionTriple:
        return (version[0], version[1], version[2] + 1)

    def decrement_version(
            self, version: RedpandaVersionTriple) -> RedpandaVersionTriple:
        return (version[0], version[1], version[2] - 1)

    def get_latest_major_version(self) -> RedpandaVersionTriple:
        return self.installer.latest_for_line(self.cur_version[0:2])[0]

    def setUp(self):
        pass

    def load_version_range(
            self, initial_version: RedpandaVersion,
            stop_version: RedpandaVersionTriple
    ) -> List[RedpandaVersionTriple]:
        """
        For tests that do upgrades: find all the latest versions from feature branches
        between the initial version and the head version.  Result is a list, inclusive of both initial
        version and head.
        """

        k = 0
        v = stop_version
        versions = [v]
        while v[2] > 1:
            v = self.decrement_version(v)
            self.logger.info(f'v: {v}')
            versions.insert(0, v)
        while (v[0], v[1]) != initial_version[0:2]:
            k += 1

            v = self.redpanda._installer.highest_from_prior_feature_version(v)
            self.logger.info(f'v: {v}')
            versions.insert(0, v)
            while v[2] > 1 and v != initial_version:
                v = self.decrement_version(v)
                self.logger.info(f'v: {v}')
                versions.insert(0, v)

            # Protect against infinite loop if something is wrong with our version finding
            if k > 100:
                raise RuntimeError(
                    f"Failed to hit expected oldest version, v={v}")

        return versions

    def client(self) -> DefaultClient:
        return self._client

    def create_topic(self, topic_name: str, num_partitions: int):
        spec = TopicSpec(name=topic_name,
                         partition_count=num_partitions,
                         replication_factor=3,
                         segment_bytes=33554432)
        self.client().create_topic(spec)
        self._topics.append(spec)

    def create_consumer_swarm(self, num_consumers: int, records: int,
                              topic: TopicSpec, commit_interval_ms: int,
                              reset_behavior: str) -> ConsumerSwarm:
        return ConsumerSwarm(self.test_context,
                             self.redpanda,
                             topic.name,
                             self._cg_name,
                             num_consumers,
                             records,
                             properties={
                                 "auto.offset.reset": reset_behavior,
                                 "enable.auto.commit": "true",
                                 "auto.commit.interval.ms": commit_interval_ms,
                             })

    def create_producers(self) -> List[VerifiableProducer]:
        producers: List[VerifiableProducer] = []
        for t in self._topics:
            producers.append(
                VerifiableProducer(self.test_context, 1, self.redpanda,
                                   t.name))
        return producers

    def is_a_leader(self, node) -> bool:
        """
        Returns true if node is leader for some partition, and false otherwise.
        """
        id = self.redpanda.idx(node)
        partitions = self._admin.get_partitions(node=node)
        has_leadership = False
        for p in partitions:
            if p["leader"] == id:
                self.logger.debug(f"{node.name} has leadership for {p}")
                has_leadership = True
        return has_leadership

    def in_maintenance_mode(self, node):
        status = self._admin.maintenance_status(node)
        return status["draining"]

    def verify_maintenance_status(self, node: ClusterNode, enabled: bool):
        node_id = self.redpanda.node_id(node)
        statuses = self._rpk.cluster_maintenance_status()
        rpk_status = None
        for status in statuses:
            if status.node_id == node_id:
                rpk_status = status
                break
        if rpk_status is None:
            return False

        admin_status = self._admin.maintenance_status(node)
        self.logger.debug(
            f'Maintenance status from admin for {node.name}: {admin_status}')

        return admin_status["draining"] == rpk_status.enabled == enabled

    def in_maintenance_mode_fully(self, node):
        status = self._admin.maintenance_status(node)
        if all([key in status
                for key in ['finished', 'errors', 'partitions']]):
            return status['finished'] and not status['errors'] and status[
                'partitions'] > 0
        else:
            return False

    def find_node_in_maintenance(self) -> Optional[ClusterNode]:
        status = self._rpk.cluster_maintenance_status()
        for s in status:
            if s.enabled:
                self.logger.debug(
                    f'Found node {s.node_id} in maintenance status')
                return self.redpanda.get_node_by_id(s.node_id)
        self.logger.info('No node found in maintenance status')
        return None

    def enable_maintenance(self, node):
        self.logger.debug(
            f'Checking that node {node.name} is not in maintenance mode')
        wait_until(lambda: self.verify_maintenance_status(node, False),
                   timeout_sec=30,
                   backoff_sec=5)

        self.logger.debug(
            f'Waiting for node {node.name} to enter maintenance mode')
        self._rpk.cluster_maintenance_enable(node, wait=True)
        assert self.in_maintenance_mode(
            node), f'{node.name} not in expected maintenance mode'

        def has_drained():
            """
            as we wait for leadership to drain, also print out maintenance mode
            status. this is useful for debugging to detect if maintenance mode
            has been lost or disabled for some unexpected reason.
            """
            status = self._admin.maintenance_status(node)
            self.logger.debug(f"Maintenance status for {node.name}: {status}")
            return not self.is_a_leader(node)

        self.logger.debug(f'Waiting for node {node.name} leadership to drain')
        wait_until(has_drained, timeout_sec=60, backoff_sec=10)

        self.logger.debug(
            f'Waiting for node {node.name} maintenance mode to complete')
        wait_until(lambda: self.in_maintenance_mode_fully(node),
                   timeout_sec=60,
                   backoff_sec=10)

    def disable_maintenance(self, node):
        self.logger.debug(f'Disabling maintenance mode on node {node.name}')
        self._rpk.cluster_maintenance_disable(node)

        self.logger.debug(
            f'Waiting for maintenance mode to exit on node {node.name}')
        wait_until(lambda: not self.in_maintenance_mode(node),
                   timeout_sec=30,
                   backoff_sec=5)

        self.logger.debug(
            f'Waiting for leadership to be restored on node {node.name}')
        wait_until(lambda: self.is_a_leader(node),
                   timeout_sec=120,
                   backoff_sec=10)

    @cluster(num_nodes=7)
    @parametrize(run_time_sec=120,
                 num_consumers=10,
                 partition_move_interval=10,
                 reverse_tolerance=10_000,
                 version_pause_interval_sec=600)
    def test_consumer_group_repro(self, run_time_sec: int, num_consumers: int,
                                  partition_move_interval: int,
                                  reverse_tolerance: int,
                                  version_pause_interval_sec: int):
        """
        Attempts reproduction of the issue
        """
        versions = self.load_version_range(self.cur_version,
                                           self.final_version)

        consumers: List[ConsumerSwarm] = []

        producers: List[VerifiableProducer] = []

        def group_is_ready():
            gr = self._rpk.group_describe(self._cg_name, summary=True)
            self.logger.debug(
                f'State: {gr.state}, members: {gr.members}, expected: {len(self._topics) * num_consumers}'
            )
            return gr.state == "Stable" and gr.members == len(
                self._topics) * num_consumers

        def initialize_everything():
            self.create_topic("large_topic", 350)
            self.create_topic("small_topic", 10)
            for t in self._topics:
                consumers.append(
                    self.create_consumer_swarm(
                        num_consumers=num_consumers,
                        records=1_000_000_000,
                        topic=t,
                        commit_interval_ms=10,
                        # I want to set this to 'error' but I can never get the consumers to stabilize
                        reset_behavior="earliest"))

            producers.extend(self.create_producers())
            self.logger.info("Starting producers")
            for p in producers:
                p.start()

            def all_consumers_present(expected_count: int):
                gr = self._rpk.group_describe(self._cg_name, summary=True)
                self.logger.debug(
                    f'State: {gr.state}, members: {gr.members}, expected: {expected_count}'
                )
                return gr.members == expected_count

            self.logger.info("Starting consumers")
            for c in consumers:
                c.start()

            expected_count = len(self._topics) * num_consumers

            wait_until(
                lambda: all_consumers_present(expected_count),
                timeout_sec=60,
                err_msg=
                f'Group {self._cg_name} did not obtain {expected_count} members'
            )

            wait_until(group_is_ready,
                       timeout_sec=60,
                       err_msg=f'Group {self._cg_name} did not stablize')

        # Monitor offsets and alert on backwards offset
        def monitor_offsets() -> bool:
            retries = 5
            while retries > 0:
                try:
                    gr = self._rpk.group_describe(self._cg_name)
                    break
                except RpkException as e:
                    retries -= 1
                    if 'timed out' in e.msg or e.returncode is None:
                        self.logger.info(f'Timeout describing group {e}')
                        if retries <= 0:
                            self.logger.info(f'Retries exhausted, failing')
                            raise e

            for item in gr.partitions:
                offset = item.current_offset or -1
                diff = offset - prev_offsets[item.topic][item.partition]

                if diff < -reverse_tolerance:
                    self.logger.error(
                        f'Offset moved backwards for topic outside of tolerance {reverse_tolerance}: {item.topic}, partition {item.partition}. Last offset: {prev_offsets[item.topic][item.partition]}, new offset: {offset}'
                    )
                    return False
                elif diff < 0:
                    self.logger.info(
                        f'Tolerated o ffset moved backwards for topic {item.topic}, partition {item.partition}. Last offset: {prev_offsets[item.topic][item.partition]}, new offset: {offset}'
                    )

                prev_offsets[item.topic][item.partition] = offset

            return True

        def check_consumers():
            for c in consumers:
                reset_consumer = False
                for n in c.nodes:
                    if not c.is_alive(n):
                        reset_consumer = True
                        self.logger.info(f"Consumer {n.account.hostname} died")
                if reset_consumer:
                    self.logger.info(f"Resetting consumer {c}")
                    c.stop()
                    c.start()

        started = False
        prev_offsets = {}
        for t in self._topics:
            prev_offsets[t.name] = {p: -1 for p in range(t.partition_count)}
        saw_backwards: bool = False

        self.logger.info(
            f"Beginning burn in process, here we will run RP on each version for {version_pause_interval_sec} seconds before upgrading to the next version"
        )
        for current_version in self.upgrade_through_versions(versions):
            upgrade_time = time.time()
            self.logger.info(f'Upgraded to {current_version}')
            if not started:
                initialize_everything()
                started = True

            while time.time() - upgrade_time < version_pause_interval_sec:
                self.logger.info(
                    f'Waiting for {version_pause_interval_sec} seconds before upgrading to the next version'
                )

                saw_backwards = not monitor_offsets()
                if saw_backwards:
                    break

                check_consumers()
                time.sleep(1)

            if (current_version[0], current_version[1],
                    current_version[2] + 1) == self.final_version:
                self.logger.info(
                    "About to upgrade to final version, setting kafka-cg logger"
                )
                self.redpanda.update_log_config(
                    LoggingConfig('info',
                                  logger_levels={
                                      'kafka': 'trace',
                                      'kafka-cg': 'trace'
                                  }))

        assert not saw_backwards, "Saw offsets go backwards during burn in!"

        self.logger.info("Burn in complete - Starting test")
        start_time = time.time()

        last_partition_move = time.time() + partition_move_interval

        # def check_move_partition(last_partition_move: int) -> int:
        #     self.logger.info(
        #         f'{time.time()} {last_partition_move} {partition_move_interval}'
        #     )
        #     if time.time() - last_partition_move > partition_move_interval:
        #         old_leader = self._admin.get_partition_leader(
        #             namespace='kafka', topic='__consumer_offsets', partition=0)
        #         self.logger.info(
        #             f"Moving kafka/__conumser_offsets/0 from {old_leader}")
        #         self._admin.partition_transfer_leadership(
        #             'kafka', '__consumer_offsets', 0)
        #         self.logger.info("Awaiting stable leadership")
        #         self._admin.await_stable_leader(namespace='kafka',
        #                                         topic='__consumer_offsets',
        #                                         partition=0)
        #         new_leader = self._admin.get_partition_leader(
        #             namespace='kafka', topic='__consumer_offsets', partition=0)
        #         self.logger.info(
        #             f"Leadership transfered from {old_leader} to {new_leader}")
        #         last_partition_move = time.time()
        #     return last_partition_move

        def swap_maintenance_mode(enable: bool):
            try:
                if enable:
                    co_leader = self._admin.get_partition_leader(
                        namespace='kafka',
                        topic='__consumer_offsets',
                        partition=0)
                    node = self.redpanda.get_node_by_id(co_leader)
                    self.logger.info(
                        f'Placing node {node.name} ({co_leader}) into maintenance mode'
                    )
                    self.enable_maintenance(node)
                    self.logger.info(f'Restarting node {node.name}')
                    self.redpanda.restart_nodes([node])
                else:
                    node_in_maintenance = self.find_node_in_maintenance()
                    if node_in_maintenance is not None:
                        self.logger.info(
                            f'Removing node {node_in_maintenance.name} from maintenance mode'
                        )
                        self.disable_maintenance(node_in_maintenance)
                    else:
                        self.logger.info("no nod in maintenance mode found")
            except Exception as e:
                self.logger.info(
                    f'Failed to swap maintenance mode, will try again: {e}')

        in_maintenance_mode = False
        while time.time() - start_time < run_time_sec:
            saw_backwards = not monitor_offsets()
            if saw_backwards:
                break

            check_consumers()
            if time.time() - last_partition_move > partition_move_interval:
                swap_maintenance_mode(not in_maintenance_mode)
                in_maintenance_mode = not in_maintenance_mode
                last_partition_move = time.time()

            time.sleep(1)

        self.logger.info("Test ending, stopping producer")
        for p in producers:
            p.stop()

        self.logger.info("Test ending, stopping consumer")
        for c in consumers:
            c.stop()

        assert not saw_backwards, "Saw offsets go backwards!"
