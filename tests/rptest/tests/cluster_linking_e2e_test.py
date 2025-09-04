# Copyright 2025 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

from connectrpc.errors import ConnectError, ConnectErrorCode

from ducktape.utils.util import wait_until

from rptest.clients.admin.v2 import Admin as AdminV2
from rptest.clients.admin.proto.redpanda.core.admin.v2 import (
    shadow_link_pb2,
    shadow_link_pb2_connect,
)
from rptest.clients.rpk import RpkPartition
from rptest.services.cluster import cluster
from rptest.services.multi_cluster_services import (
    Cluster,
    MultiClusterServices,
    ServiceType,
)
from rptest.tests.cluster_linking_test_base import ShadowLinkTestBase
from rptest.tests.redpanda_test import RedpandaTest
from rptest.util import expect_exception, wait_until_result

from google.protobuf import duration_pb2

from typing import Iterator


class MultiClusterTestBase(RedpandaTest):
    def __init__(self, test_context, *args, **kwargs):
        super().__init__(test_context=test_context, *args, **kwargs)

    def basic_ops(self, services: MultiClusterServices):
        def at_least_one_topic_exists(services: MultiClusterServices, node: Cluster):
            topics = services.list_topics(node, detailed=True)
            return len(topics) > 0, topics

        topic = "test-topic"
        services.create_topic(services.primary, topic, partitions=3, replicas=3)
        p_topics = wait_until_result(
            lambda: at_least_one_topic_exists(services, services.primary),
            timeout_sec=30,
            err_msg="Failed to create a single topic on the primary cluster",
        )

        services.create_topic(services.secondary, topic, partitions=3, replicas=3)
        s_topics = wait_until_result(
            lambda: at_least_one_topic_exists(services, services.secondary),
            timeout_sec=30,
            err_msg="Failed to create a single topic on the secondary cluster",
        )

        assert p_topics == s_topics, (
            f"Expected same topics on both clusters, got {p_topics=} vs {s_topics=}"
        )

        assert len(p_topics) == 1 and p_topics[0][0] == topic, (
            f"Expected {topic=}, got {p_topics=}"
        )

        status_json = services.primary.admin.get_status_ready()
        assert status_json["status"] == "ready", f"Expected ready, got {status_json=}"

        if services.secondary.is_redpanda:
            status_json = services.secondary.admin.get_status_ready()
            assert status_json["status"] == "ready", (
                f"Expected ready, got {status_json=}"
            )
        else:
            with expect_exception(NotImplementedError, lambda e: True):
                services.secondary.admin.get_status_ready()


class MultiClusterRedpandaTest(MultiClusterTestBase):
    """
    Just verifies MultiClusterServices for now. rp + rp & rp + kafka
    """

    def __init__(self, test_context, *args, **kwargs):
        super().__init__(test_context=test_context, num_brokers=3, *args, **kwargs)

        self.test_context = test_context

    def setUp(self):
        # MultiClusterServices will set itself up
        pass

    @cluster(num_nodes=6)
    def test_basic_ops(self):
        with MultiClusterServices(
            self.test_context,
            self.logger,
            self.redpanda,
            secondary_type=ServiceType.REDPANDA,
            num_brokers=3,
        ) as services:
            assert services.secondary.is_redpanda, (
                f"Expected Redpanda service, got {services.secondary}"
            )
            self.basic_ops(services)


class MultiClusterKafkaTest(MultiClusterTestBase):
    """
    Just verifies MultiClusterServices for now. rp + rp & rp + kafka
    """

    def __init__(self, test_context, *args, **kwargs):
        super().__init__(test_context=test_context, num_brokers=3, *args, **kwargs)

        self.test_context = test_context

    def setUp(self):
        # MultiClusterServices will set itself up
        pass

    @cluster(num_nodes=7)
    def test_basic_ops(self):
        with MultiClusterServices(
            self.test_context,
            self.logger,
            self.redpanda,
            secondary_type=ServiceType.KAFKA,
            num_brokers=3,
        ) as services:
            assert services.secondary.is_kafka, (
                f"Expected Kafka service, got {services.secondary}"
            )
            self.basic_ops(services)


class ShadowLinkBasicTests(ShadowLinkTestBase):
    @cluster(num_nodes=6)
    def test_create_simple_link(self):
        create_res = self.create_link("test-link")
        self.logger.info(f"Create shadow link result: {create_res.shadow_link}")

        links = self.list_links()
        assert len(links) == 1, f"Expected exactly one shadow link, got {len(links)}"
        assert links[0].name == "test-link", (
            f"Expected shadow link name to be 'test-link', got {links[0].name}"
        )

        got_link = self.get_link(name="test-link")
        assert got_link.name == "test-link", (
            f"Expected shadow link name to be 'test-link', got {got_link.name}"
        )

        try:
            self.get_link(name="non-existent-link")
            assert False, "Should not have gotten a non-existent link"
        except ConnectError as e:
            assert e.code == ConnectErrorCode.NOT_FOUND, (
                f"Expected NOT_FOUND error code, got {e.code}"
            )

    @cluster(num_nodes=6)
    def test_can_not_create_more_than_one_link(self):
        resp = self.create_link("test-link")

        assert resp.shadow_link.name == "test-link", (
            f"Expected shadow link name to be 'test-link', got {resp.shadow_link.name}"
        )

        # Now attempt to create a second one with the same name
        try:
            self.create_link("test-link")
            assert False, (
                "Should not have been able to create a second link with the same name"
            )
        except ConnectError as e:
            assert e.code == ConnectErrorCode.ALREADY_EXISTS, (
                f"Expected {ConnectErrorCode.ALREADY_EXISTS}, got {e.code}"
            )

        # Now create a second one with a different name
        try:
            self.create_link("test-link-2")
            assert False, "Should not have been able to create a second link"
        except ConnectError as e:
            assert e.code == ConnectErrorCode.RESOURCE_EXHAUSTED, (
                f"Expected {ConnectErrorCode.RESOURCE_EXHAUSTED}, got {e.code}"
            )


class ShadowLinkTopicPropertyMirroringTest(ShadowLinkTestBase):
    """
    Tests that validate mirroring of topic properties
    """

    @cluster(num_nodes=6)
    def test_topic_mirroring(self):
        """
        This test will create a shadow link and validate that topics are automatically created and properties are replicated
        """
        req = self.create_default_link_request(link_name="test-link")

        topic_filters: list[shadow_link_pb2.NameFilter] = [
            shadow_link_pb2.NameFilter(
                pattern_type=shadow_link_pb2.PATTERN_TYPE_LITERAL,
                filter_type=shadow_link_pb2.FILTER_TYPE_INCLUDE,
                name="*",
            )
        ]

        topic_sync_options = shadow_link_pb2.TopicMetadataSyncOptions(
            interval=duration_pb2.Duration(seconds=1), topic_filters=topic_filters
        )

        req.shadow_link.configurations.topic_metadata_sync_options.CopyFrom(
            topic_sync_options
        )

        self.create_link_with_request(req=req)

        # Create a topic on the source cluster and see that it gets created on the shadow
        topic_name = "test-topic"
        self.source_cluster_rpk.create_topic(topic=topic_name, partitions=1, replicas=3)

        def topic_exists_on_target() -> tuple[bool, list[RpkPartition]]:
            topic_partitions = list(
                self.target_cluster_rpk.describe_topic(topic=topic_name)
            )
            return len(topic_partitions) != 0, topic_partitions

        topic_partitions: list[RpkPartition] = wait_until_result(
            topic_exists_on_target,
            timeout_sec=30,
            backoff_sec=1,
            err_msg=f"Failed to replicate topic {topic_name}",
            retry_on_exc=True,
        )
        self.logger.info(f"Topic partitions: {topic_partitions}")
        assert len(topic_partitions) == 1, (
            f"Expected one partition, got {len(topic_partitions)}"
        )
        assert len(topic_partitions[0].replicas) == 3, (
            f"Expected 3 replicas, got {len(topic_partitions[0].replicas)}"
        )

        self.source_cluster_rpk.add_topic_partitions(topic=topic_name, additional=2)

        def topic_has_three_partitions() -> bool:
            topic_partitions = list(
                self.target_cluster_rpk.describe_topic(topic=topic_name)
            )
            return len(topic_partitions) == 3

        wait_until(
            topic_has_three_partitions,
            timeout_sec=30,
            backoff_sec=1,
            err_msg=f"Failed to replicate partition count for topic {topic_name}",
            retry_on_exc=True,
        )

        # Verify that the _schemas topic was not created
        assert (
            len(list(self.target_cluster_rpk.describe_topic(topic="_schemas"))) == 0
        ), "The _schemas topic should not exist"

        # Now verify that the topic properties are replicated
        self.source_cluster_rpk.alter_topic_config(
            topic=topic_name, set_key="max.message.bytes", set_value="1"
        )
        self.source_cluster_rpk.alter_topic_config(
            topic=topic_name, set_key="cleanup.policy", set_value="compact,delete"
        )
        self.source_cluster_rpk.alter_topic_config(
            topic=topic_name,
            set_key="message.timestamp.type",
            set_value="LogAppendTime",
        )
        self.source_cluster_rpk.alter_topic_config(
            topic=topic_name, set_key="replication.factor", set_value="1"
        )

        def wait_for_properties_to_sync() -> bool:
            configs = self.target_cluster_rpk.describe_topic_configs(topic=topic_name)
            return (
                configs["max.message.bytes"][0] == "1"
                and configs["cleanup.policy"][0] == "compact,delete"
                and configs["message.timestamp.type"][0] == "LogAppendTime"
            )

        wait_until(
            wait_for_properties_to_sync,
            timeout_sec=30,
            backoff_sec=1,
            err_msg="Timed out waiting for properties to sync",
        )

        # Verify that the replication factor did not change
        topic_info = list(self.target_cluster_rpk.describe_topic(topic=topic_name))
        assert len(topic_info[0].replicas) == 3, (
            f"Expected replication factor to remain 3, got {len(topic_info[0].replicas)}"
        )
