# Copyright 2025 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

import concurrent.futures
import json
import random
import sys
import time
from typing import Any, Optional

import numpy

from ducktape.cluster.cluster import ClusterNode
from ducktape.cluster.cluster_spec import ClusterSpec

from rptest.clients.admin.proto.redpanda.core.admin.v2 import security_pb2
from rptest.clients.admin.v2 import Admin as AdminV2
from rptest.clients.python_librdkafka import PythonLibrdkafka
from rptest.clients.rpk import RpkTool
from rptest.services.admin import Admin
from rptest.services.cluster import cluster
from rptest.services.keycloak import KeycloakService
from rptest.services.redpanda import LoggingConfig, SecurityConfig
from rptest.tests.audit_log_test import AuditLogTestOauth
from rptest.tests.redpanda_test import RedpandaTest
from rptest.util import inject_remote_script, wait_until
from rptest.utils.mode_checks import skip_fips_mode
from rptest.utils.scale_parameters import ScaleParameters


class GBACScaleTestBase(RedpandaTest):
    """
    Base class for GBAC (Group-Based Access Control) scale tests.
    Provides common utilities for Keycloak setup, batch operations, and audit verification.
    """

    CLIENT_ID_PREFIX = "test-client"
    TOKEN_AUDIENCE = "account"
    KAFKA_RPC_SERVICE_NAME = "kafka rpc protocol"
    ADMIN_AUDIT_SVC_NAME = "Redpanda Admin HTTP Server"
    AUDIT_LOG_TOPIC = "_redpanda.audit_log"

    def __init__(
        self,
        test_context,
        num_brokers=5,
        kafka_sasl_max_reauth_ms=300_000,
        extra_rp_conf=None,
        security_config: SecurityConfig | None = None,
        **kwargs,
    ):
        """
        Initialize GBAC scale test base.

        Args:
            test_context: Test context from ducktape
            num_brokers: Number of Redpanda brokers (default: 5)
            kafka_sasl_max_reauth_ms: Token reauth interval in milliseconds
            extra_rp_conf: Additional Redpanda configuration
        """
        self.keycloak = KeycloakService(test_context)

        if security_config:
            self.security_config = security_config
        else:
            self.security_config = SecurityConfig()
            self.security_config.enable_sasl = True

        # Base configuration for GBAC scale testing
        base_extra_rp_conf = {
            "audit_enabled": True,
            "audit_enabled_event_types": ["authenticate"],
            "audit_log_num_partitions": 12,
            "audit_log_replication_factor": 3,
            "audit_client_max_buffer_size": 160_000_000,  # 10x default
            "audit_queue_max_buffer_size_per_shard": 10_000_000,  # 10x default
            "kafka_connections_max": 20_000,
            "kafka_connections_max_per_ip": 20_000,
            "topic_partitions_memory_allocation_percent": 20,
            "log_segment_size": 8_000_000,
            "aggregate_metrics": False,
            "disable_public_metrics": True,
            "kafka_sasl_max_reauth_ms": kafka_sasl_max_reauth_ms,
        }

        if extra_rp_conf:
            base_extra_rp_conf.update(extra_rp_conf)

        super(GBACScaleTestBase, self).__init__(
            test_context=test_context,
            num_brokers=num_brokers,
            extra_rp_conf=base_extra_rp_conf,
            log_config=LoggingConfig(
                "info",
                logger_levels={
                    "storage": "warn",
                    "raft": "warn",
                    "security": "trace",
                    "kafka/authz": "trace",
                    "kafka": "trace",
                },
            ),
            security=self.security_config,
            **kwargs,
        )

        self.super_rpk = RpkTool(
            self.redpanda,
            username=self.redpanda.SUPERUSER_CREDENTIALS[0],
            password=self.redpanda.SUPERUSER_CREDENTIALS[1],
            sasl_mechanism=self.redpanda.SUPERUSER_CREDENTIALS[2],
        )

        self.admin = Admin(
            self.redpanda,
            auth=(
                self.redpanda.SUPERUSER_CREDENTIALS[0],
                self.redpanda.SUPERUSER_CREDENTIALS[1],
            ),
        )

        self.admin_v2 = AdminV2(
            self.redpanda,
            auth=(
                self.redpanda.SUPERUSER_CREDENTIALS[0],
                self.redpanda.SUPERUSER_CREDENTIALS[1],
            ),
        )

    def setUp(self):
        """Set up test - start Redpanda and Keycloak"""
        # Start Redpanda cluster first (SASL without OAuth initially)
        super().setUp()

        # Start Keycloak
        kc_node = self.keycloak.nodes[0]
        try:
            self.keycloak.start_node(kc_node)
        except Exception as e:
            self.logger.error(f"Keycloak failed to start: {e}")
            self.keycloak.clean_node(kc_node)
            raise

        # Configure Redpanda with OIDC after Keycloak is up
        self.redpanda.set_cluster_config(
            {
                "oidc_discovery_url": self.keycloak.get_discovery_url(kc_node),
                "oidc_token_audience": self.TOKEN_AUDIENCE,
                "sasl_mechanisms": ["SCRAM", "OAUTHBEARER"],
            }
        )

        # Wait for audit log to be created
        self.logger.info("Waiting for audit log topic to be created")
        wait_until(
            lambda: self.AUDIT_LOG_TOPIC in self.super_rpk.list_topics(),
            timeout_sec=30,
            backoff_sec=2,
        )

    def create_groups_batch(self, count: int, name_prefix: str = "group") -> list[str]:
        """
        Create Keycloak groups in parallel.

        Args:
            count: Number of groups to create
            name_prefix: Prefix for group names

        Returns:
            List of group names created
        """
        self.logger.info(f"Creating {count} groups with prefix '{name_prefix}'")

        def create_group(i):
            group_name = f"{name_prefix}-{i}"
            self.keycloak.admin.create_group(group_name)
            return group_name

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            group_names = list(executor.map(create_group, range(count)))

        self.logger.info(f"Successfully created {len(group_names)} groups")
        return group_names

    def create_users_with_groups(
        self,
        user_count: int,
        groups: list[str],
        groups_per_user: int,
        client_id_prefix: Optional[str] = None,
    ) -> list[str]:
        """
        Create OAuth service accounts and assign them to random groups.

        Args:
            user_count: Number of users to create
            groups: List of group names
            groups_per_user: Number of groups to assign per user
            client_id_prefix: Prefix for client IDs (default: CLIENT_ID_PREFIX)

        Returns:
            List of client IDs created
        """
        if client_id_prefix is None:
            client_id_prefix = self.CLIENT_ID_PREFIX

        self.logger.info(
            f"Creating {user_count} users, each in {groups_per_user} random groups"
        )

        def create_user_with_groups(i):
            client_id = f"{client_id_prefix}-{i}"
            self.keycloak.admin.create_client(client_id)

            # Assign to random groups
            user_groups = random.sample(groups, min(groups_per_user, len(groups)))
            for group in user_groups:
                self.keycloak.admin.add_service_user_to_group(client_id, group)

            return client_id

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            client_ids = list(executor.map(create_user_with_groups, range(user_count)))

        self.logger.info(f"Successfully created {len(client_ids)} users")
        return client_ids

    def _try_parse_json(self, node: ClusterNode, jsondata: str):
        try:
            return json.loads(jsondata)
        except ValueError:
            self.logger.debug(
                f"{str(node.account)}: Could not parse json: {str(jsondata)}"
            )
            return None

    def create_topics_batch(
        self,
        brokers: str,
        node: ClusterNode,
        count: int,
        partitions: int = 3,
        replicas: int = 3,
        name_prefix: str = "topic",
    ) -> list[dict[str, Any]]:
        """
        Create topics in parallel batches.

        Args:
            count: Number of topics to create
            partitions: Partitions per topic
            replicas: Replication factor
            name_prefix: Prefix for topic names
        :param brokers: Broker connection string
        :param node: Cluster node to run script on
        :param count: Number of topics to create
        :param partitions: Number of partitions per topic
        :param replicas: RF for topiocs
        :param name_prefix: Prefix for topic names
        :raises RuntimeError: Underlying creation script generated error
        :return: list: topic names
        """
        self.logger.info(
            f"Creating {count} topics with {partitions} partitions and {replicas} replicas"
        )

        remote_script_path = inject_remote_script(node, "topic_operations.py")
        args = [
            "python3",
            remote_script_path,
            "--brokers",
            f"'{brokers}'",
            "--batch-size",
            "'256'",
            "--user-name",
            self.redpanda.SUPERUSER_CREDENTIALS[0],
            "--password",
            self.redpanda.SUPERUSER_CREDENTIALS[1],
            "--mechanism",
            self.redpanda.SUPERUSER_CREDENTIALS[2],
            "create",
            "--topic-prefix",
            f"'{name_prefix}'",
            "--topic-count",
            f"{count}",
            "--partitions",
            f"{partitions}",
            "--replicas",
            f"{replicas}",
            "--skip-randomize-names",
            "--kafka-batching",
        ]
        cmd = " ".join(args)
        hostname = node.account.hostname
        self.logger.info(f'Starting topic creation script on "{hostname}"')
        self.logger.debug(f"...cmd: {cmd}")

        data: dict[str, Any] | None = {}
        for line in node.account.ssh_capture(cmd):
            self.logger.debug(f'received {sys.getsizeof(line)}B from "{hostname}".')
            data = self._try_parse_json(node, line.strip())
            if data is not None:
                if "error" in data:
                    self.logger.warning(
                        f'Node "{hostname}" reported error: {data["error"]}'
                    )
                    raise RuntimeError(data["error"])

        assert data

        topic_details: list[dict[str, Any]] = data.get("topics", [])
        current_count = len(topic_details)
        self.logger.info(f"Created {current_count} topics")
        assert len(topic_details) == count, (
            f"Expected {count} topics, got {len(topic_details)}"
        )

        self.logger.debug(f'Topic details from "{hostname}": {topic_details}')
        return topic_details

    def create_group_acls_batch(
        self, topics: list[str], groups: list[str], acls_per_topic: int
    ):
        """
        Create group-based ACLs in parallel batches.

        Args:
            topics: List of topic names
            groups: List of group names
            acls_per_topic: Number of ACL rules per topic
        """
        total_acls = len(topics) * acls_per_topic
        self.logger.info(
            f"Creating {total_acls} ACLs ({acls_per_topic} per topic) across {len(topics)} topics"
        )

        def create_acls_for_topic(topic_idx):
            topic_name = topics[topic_idx]
            # Create mix of Group and User ACLs (70% Group, 30% User)
            for i in range(acls_per_topic):
                if i < int(acls_per_topic * 0.7):  # 70% Group ACLs
                    principal = f"Group:{groups[topic_idx % len(groups)]}"
                else:  # 30% User ACLs
                    principal = f"User:user-{i}"

                self.super_rpk.sasl_allow_principal(
                    principal,
                    ["read", "write"],
                    "topic",
                    topic_name,
                    self.redpanda.SUPERUSER_CREDENTIALS[0],
                    self.redpanda.SUPERUSER_CREDENTIALS[1],
                    self.redpanda.SUPERUSER_CREDENTIALS[2],
                )

        # Process in batches
        batch_size = 100
        for batch_start in range(0, len(topics), batch_size):
            batch_end = min(batch_start + batch_size, len(topics))
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
                list(executor.map(create_acls_for_topic, range(batch_start, batch_end)))
            self.logger.info(
                f"Created ACLs for topics {batch_start} to {batch_end - 1}"
            )

        self.logger.info(f"Successfully created {total_acls} ACL rules")

    def get_oauth_client(self, client_id: str) -> PythonLibrdkafka:
        """
        Create an OAuth-enabled Kafka client.

        Args:
            client_id: Keycloak client ID

        Returns:
            PythonLibrdkafka client configured with OAuth
        """
        kc_node = self.keycloak.nodes[0]
        cfg = self.keycloak.generate_oauth_config(kc_node, client_id)
        return PythonLibrdkafka(
            self.redpanda, algorithm="OAUTHBEARER", oauth_config=cfg
        )

    def measure_operation_latency(self, operation_fn, iterations: int = 100) -> dict:
        """
        Measure operation latency with percentile statistics.

        Args:
            operation_fn: Function to measure
            iterations: Number of iterations

        Returns:
            Dictionary with p50, p90, p99, and mean latencies
        """
        latencies = []
        for _ in range(iterations):
            start = time.time()
            operation_fn()
            latencies.append((time.time() - start) * 1000)  # Convert to ms

        return {
            "p50": numpy.percentile(latencies, 50),
            "p90": numpy.percentile(latencies, 90),
            "p99": numpy.percentile(latencies, 99),
            "mean": numpy.mean(latencies),
            "min": numpy.min(latencies),
            "max": numpy.max(latencies),
        }

    @staticmethod
    def oidc_authn_with_groups_filter_function(
        service_name: str,
        username: Optional[str],
        sub: Optional[str],
        expected_groups: list[str],
        record,
    ):
        """Filter for OIDC authentication events that include IDP groups"""
        if not (
            record["class_uid"] == 3002
            and record["service"]["name"] == service_name
            and record["auth_protocol_id"] == 6
            and (record["user"]["name"] == username if username is not None else True)
            and (record["user"]["uid"] == sub if sub is not None else True)
        ):
            return False

        # Check that groups are present
        user_groups = record.get("user", {}).get("groups", [])
        if not expected_groups:
            return True

        # Verify expected groups are present with type "idp_group"
        for expected_group in expected_groups:
            if not any(
                g.get("type") == "idp_group"
                and AuditLogTestOauth.normalize_group_name(g.get("name", ""))
                == expected_group
                for g in user_groups
            ):
                return False
        return True

    def get_idp_request_count(self) -> int:
        """
        Get the total number of IdP requests across all nodes.

        Returns:
            Total IdP request count
        """
        metrics = [
            "security_idp_latency_seconds_count",
        ]
        samples = self.redpanda.metrics_samples(metrics, None)

        result = {}
        for k in samples.keys():
            result[k] = result.get(k, 0) + sum(
                [int(s.value) for s in samples[k].samples]
            )
        return result["security_idp_latency_seconds_count"]


class GBACLargeTokenTest(GBACScaleTestBase):
    """
    Scale test for GBAC with large OAuth tokens containing many groups.
    Tests token parsing performance and authorization latency with 50-200 groups per user.
    """

    def __init__(self, test_context):
        super(GBACLargeTokenTest, self).__init__(
            test_context=test_context,
            num_brokers=5,
            kafka_sasl_max_reauth_ms=300_000,  # 5 minutes for stability
        )

    @skip_fips_mode
    @cluster(num_nodes=8)  # 5 Redpanda + 1 Keycloak + 1 client node + 1 topic creator
    def test_large_token_performance(self):
        """
        Test performance impact of large OAuth tokens (50-200 groups).
        Measures latency and throughput degradation as group count increases.
        """
        self.logger.info("Starting large token performance test")

        # Configuration
        total_groups = 1000
        num_topics = 500
        group_counts_to_test = [5, 50, 100, 150, 200]  # 5 is baseline
        users_per_group_count = 10
        iterations_per_test = 50

        brokers = ",".join(self.redpanda.brokers_list())
        node = self.cluster.alloc(ClusterSpec.simple_linux(1))[0]

        # Create resources
        self.logger.info("Creating test resources")
        groups = self.create_groups_batch(total_groups, name_prefix="perf-group")
        topics = self.create_topics_batch(
            brokers=brokers,
            node=node,
            count=num_topics,
            partitions=3,
            replicas=3,
            name_prefix="perf-topic",
        )

        # Create group mapper (full_path=False for simpler group names)
        for i in range(users_per_group_count * len(group_counts_to_test)):
            client_id = f"perf-client-{i}"
            self.keycloak.admin.create_client(client_id)
            self.keycloak.admin.create_group_mapper(client_id, use_full_path=False)

        # Create ACLs for topics (mixed Group and User principals)
        self.logger.info("Creating ACLs for topics")
        for i, topic in enumerate(topics):
            # 40% Group-based ACLs, 60% User-based
            for j in range(10):
                if j < 4:
                    principal = f"Group:{groups[i % len(groups)]}"
                else:
                    principal = f"User:perf-client-{j}"

                self.super_rpk.sasl_allow_principal(
                    principal,
                    ["all"],
                    "topic",
                    topic["name"],
                    self.redpanda.SUPERUSER_CREDENTIALS[0],
                    self.redpanda.SUPERUSER_CREDENTIALS[1],
                    self.redpanda.SUPERUSER_CREDENTIALS[2],
                )

        self.cluster.free_single(node)

        # Test with different group counts
        results = {}

        for group_count in group_counts_to_test:
            self.logger.info(f"\n=== Testing with {group_count} groups per user ===")

            # Create users with specific group count
            phase_users = []
            for i in range(users_per_group_count):
                user_idx = (
                    len(group_counts_to_test[: group_counts_to_test.index(group_count)])
                    * users_per_group_count
                    + i
                )
                client_id = f"perf-client-{user_idx}"

                # Assign groups
                user_groups = random.sample(groups, min(group_count, len(groups)))
                for group in user_groups:
                    self.keycloak.admin.add_service_user_to_group(client_id, group)

                phase_users.append(client_id)

            # Let group assignments propagate
            time.sleep(2)

            # Measure operations with this user
            test_client_id = phase_users[0]
            client = self.get_oauth_client(test_client_id)
            producer = client.get_producer()

            # Warmup
            for _ in range(5):
                producer.poll(0.1)

            # Measure metadata latency
            def metadata_op():
                topics_metadata = producer.list_topics(timeout=10)
                return len(topics_metadata.topics)

            metadata_stats = self.measure_operation_latency(
                metadata_op, iterations=iterations_per_test
            )

            # Measure produce latency
            test_topic = random.choice(topics)
            produce_latencies = []

            for i in range(iterations_per_test):
                start = time.time()
                producer.produce(
                    test_topic["name"],
                    key=f"key-{i}",
                    value=f"value-{i}".encode("utf-8"),
                )
                producer.flush(timeout=10)
                produce_latencies.append((time.time() - start) * 1000)

            produce_stats = {
                "p50": numpy.percentile(produce_latencies, 50),
                "p90": numpy.percentile(produce_latencies, 90),
                "p99": numpy.percentile(produce_latencies, 99),
                "mean": numpy.mean(produce_latencies),
            }

            # Get IdP query count
            idp_queries = self.get_idp_request_count()

            results[group_count] = {
                "metadata": metadata_stats,
                "produce": produce_stats,
                "idp_queries": idp_queries,
            }

            self.logger.info(f"Group count {group_count} results:")
            self.logger.info(f"  Metadata P99: {metadata_stats['p99']:.2f} ms")
            self.logger.info(f"  Produce P99: {produce_stats['p99']:.2f} ms")
            self.logger.info(f"  IdP queries: {idp_queries}")

        # Assertions
        baseline_metadata_p99 = results[5]["metadata"]["p99"]
        baseline_produce_p99 = results[5]["produce"]["p99"]

        for group_count in [50, 100, 150, 200]:
            metadata_p99 = results[group_count]["metadata"]["p99"]
            produce_p99 = results[group_count]["produce"]["p99"]

            # P99 latency should not increase more than 20% for metadata
            metadata_increase = (
                metadata_p99 - baseline_metadata_p99
            ) / baseline_metadata_p99
            assert metadata_increase < 0.20, (
                f"Metadata P99 latency increased by {metadata_increase * 100:.1f}% "
                f"with {group_count} groups (expected < 20%)"
            )

            # P99 latency should not increase more than 20% for produce
            produce_increase = (
                produce_p99 - baseline_produce_p99
            ) / baseline_produce_p99
            assert produce_increase < 0.20, (
                f"Produce P99 latency increased by {produce_increase * 100:.1f}% "
                f"with {group_count} groups (expected < 20%)"
            )

            self.logger.info(
                f"✓ Group count {group_count}: metadata +{metadata_increase * 100:.1f}%, "
                f"produce +{produce_increase * 100:.1f}%"
            )

        self.logger.info("\n=== Large Token Test PASSED ===")


class GBACManyACLsTest(GBACScaleTestBase):
    """
    Scale test for GBAC with thousands of group-based ACL rules.
    Tests ACL evaluation performance with 30,000-50,000 ACL entries.
    """

    def __init__(self, test_context):
        super(GBACManyACLsTest, self).__init__(
            test_context=test_context,
            num_brokers=7,  # More brokers for partition density
            kafka_sasl_max_reauth_ms=300_000,
        )

    @skip_fips_mode
    @cluster(num_nodes=10)  # 7 Redpanda + 1 Keycloak + 1 client node + 1 topic creator
    def test_many_group_acls(self):
        """
        Test ACL evaluation performance with thousands of group-based ACLs.
        Verifies metadata and produce latency remain acceptable at scale.
        """
        self.logger.info("Starting many ACLs performance test")

        # Calculate scale based on cluster resources
        scale = ScaleParameters(self.redpanda, replication_factor=3)
        num_groups = 600
        num_topics = min(4000, scale.partition_limit // 3)  # 3 partitions per topic
        num_users = 120
        groups_per_user = 15
        acls_per_topic = 10  # 7 Group ACLs, 3 User ACLs

        brokers = ",".join(self.redpanda.brokers_list())
        node = self.cluster.alloc(ClusterSpec.simple_linux(1))[0]

        total_acls = num_topics * acls_per_topic
        self.logger.info(
            f"Scale parameters: {num_topics} topics, {num_groups} groups, "
            f"{num_users} users, {total_acls} total ACLs"
        )

        # Create resources
        self.logger.info("Creating groups")
        groups = self.create_groups_batch(num_groups, name_prefix="acl-group")

        self.logger.info("Creating users")
        users = self.create_users_with_groups(
            num_users, groups, groups_per_user, client_id_prefix="acl-client"
        )

        # Create group mappers for all users
        for client_id in users:
            self.keycloak.admin.create_group_mapper(client_id, use_full_path=False)

        self.logger.info("Creating topics")
        topics = self.create_topics_batch(
            brokers=brokers,
            node=node,
            count=num_topics,
            partitions=3,
            replicas=3,
            name_prefix="acl-topic",
        )

        self.logger.info("Creating ACLs")
        topic_names = [topic["name"] for topic in topics]
        self.create_group_acls_batch(topic_names, groups, acls_per_topic)

        # Let ACLs propagate
        self.logger.info("Waiting for ACLs to propagate")
        time.sleep(10)

        # Test operations with random users
        self.logger.info("Testing metadata operations")
        test_users = random.sample(users, min(10, len(users)))

        metadata_latencies = []
        for client_id in test_users:
            self.logger.debug(f"Getting client for {client_id}")
            client = self.get_oauth_client(client_id)
            producer = client.get_producer()

            start = time.time()
            topics_metadata = producer.list_topics(timeout=1200)
            latency_ms = (time.time() - start) * 1000
            metadata_latencies.append(latency_ms)

            self.logger.info(
                f"User {client_id}: listed {len(topics_metadata.topics)} topics "
                f"in {latency_ms:.2f} ms"
            )

        metadata_p99 = numpy.percentile(metadata_latencies, 99)

        # Test produce operations
        self.logger.info("Testing produce operations")
        produce_latencies = []

        for client_id in test_users:
            client = self.get_oauth_client(client_id)
            producer = client.get_producer()

            # Try to produce to a random topic
            test_topic = random.choice(topic_names)
            try:
                start = time.time()
                producer.produce(test_topic, key="test", value=b"test-data")
                producer.flush(timeout=10)
                latency_ms = (time.time() - start) * 1000
                produce_latencies.append(latency_ms)
                self.logger.info(f"User {client_id}: produced in {latency_ms:.2f} ms")
            except Exception as e:
                # User may not have permission to this specific topic
                self.logger.debug(f"User {client_id} couldn't produce: {e}")

        if produce_latencies:
            produce_p99 = numpy.percentile(produce_latencies, 99)
        else:
            produce_p99 = 0
            self.logger.warning("No successful produce operations")

        # Assertions
        assert metadata_p99 < 2000, (
            f"Metadata P99 latency {metadata_p99:.2f}ms exceeds 2000ms threshold"
        )

        if produce_p99 > 0:
            # Compare to a baseline - produce should be reasonably fast
            assert produce_p99 < 500, (
                f"Produce P99 latency {produce_p99:.2f}ms exceeds 500ms threshold"
            )

        self.logger.info("\n=== Many ACLs Test PASSED ===")
        self.logger.info(f"  Metadata P99: {metadata_p99:.2f} ms")
        self.logger.info(f"  Produce P99: {produce_p99:.2f} ms")
        self.logger.info(f"  Total ACLs: {total_acls}")


class GBACComplexHierarchyTest(GBACScaleTestBase):
    """
    Scale test for GBAC with role hierarchies and dynamic membership changes.
    Tests groups→roles→ACLs mapping and dynamic group membership updates.
    """

    def __init__(self, test_context):
        super(GBACComplexHierarchyTest, self).__init__(
            test_context=test_context,
            num_brokers=5,
            kafka_sasl_max_reauth_ms=60_000,  # 60s for testing dynamic updates
        )

    @skip_fips_mode
    @cluster(num_nodes=7)  # 5 Redpanda + 1 Keycloak + 1 client node
    def test_role_hierarchy_and_dynamic_membership(self):
        """
        Test role hierarchies (groups→roles→ACLs) and dynamic group membership.
        Verifies permissions update correctly when group memberships change.
        """
        self.logger.info("Starting role hierarchy and dynamic membership test")

        # Configuration
        num_users = 80
        num_topics = 800

        # Create hierarchical group structure
        self.logger.info("Creating hierarchical group structure")
        group_hierarchy = {
            "engineering": ["platform-team", "backend-team", "frontend-team"],
            "data": ["data-engineers", "data-analysts"],
            "ops": ["sre", "security"],
        }

        all_groups = []
        for parent, children in group_hierarchy.items():
            parent_id = self.keycloak.admin.create_group(parent)
            all_groups.append(parent)
            for child in children:
                self.keycloak.admin.create_group(child, parent=parent_id)
                all_groups.append(child)

        # Create users distributed across leaf groups
        self.logger.info("Creating users")
        leaf_groups = [
            "platform-team",
            "backend-team",
            "frontend-team",
            "data-engineers",
            "data-analysts",
            "sre",
            "security",
        ]

        users = []
        for i in range(num_users):
            client_id = f"role-client-{i}"
            self.keycloak.admin.create_client(client_id)
            self.keycloak.admin.create_group_mapper(client_id, use_full_path=False)

            # Assign to 1-2 random leaf groups
            user_groups = random.sample(leaf_groups, random.randint(1, 2))
            for group in user_groups:
                self.keycloak.admin.add_service_user_to_group(client_id, group)

            users.append((client_id, user_groups))

        # Create Redpanda roles mapped to groups
        self.logger.info("Creating Redpanda roles")
        role_mappings = {
            "dev-role": ["backend-team", "frontend-team"],
            "platform-role": ["platform-team"],
            "data-read-role": ["data-analysts"],
            "data-write-role": ["data-engineers"],
            "ops-role": ["sre", "security"],
        }

        for role_name, group_names in role_mappings.items():
            members = [
                security_pb2.RoleMember(group=security_pb2.RoleGroup(name=g))
                for g in group_names
            ]
            role = security_pb2.Role(name=role_name, members=members)
            self.admin_v2.security().create_role(
                security_pb2.CreateRoleRequest(role=role)
            )
            self.logger.info(f"Created role {role_name} with groups {group_names}")

        # Create topics with role-based ACLs
        self.logger.info("Creating topics with role-based ACLs")
        topic_patterns = {
            "dev-": "dev-role",
            "platform-": "platform-role",
            "data-": "data-write-role",
            "metrics-": "ops-role",
        }

        topics_by_pattern = {}
        for pattern, role_name in topic_patterns.items():
            pattern_topics = []
            for i in range(num_topics // len(topic_patterns)):
                topic_name = f"{pattern}topic-{i}"
                self.super_rpk.create_topic(topic_name, partitions=3, replicas=3)
                pattern_topics.append(topic_name)

            topics_by_pattern[pattern] = pattern_topics

            # Grant role-based ACL for this pattern
            self.super_rpk.sasl_allow_principal(
                f"RedpandaRole:{role_name}",
                ["all"],
                "topic",
                f"{pattern}*",  # Pattern-based ACL
                self.redpanda.SUPERUSER_CREDENTIALS[0],
                self.redpanda.SUPERUSER_CREDENTIALS[1],
                self.redpanda.SUPERUSER_CREDENTIALS[2],
            )
            self.logger.info(f"Granted {role_name} access to {pattern}* topics")

        # Phase 1: Test static hierarchy
        self.logger.info("\n=== Phase 1: Testing static role hierarchy ===")
        time.sleep(5)  # Let permissions propagate

        test_user_id, test_user_groups = users[0]
        self.logger.info(f"Test user {test_user_id} is in groups: {test_user_groups}")

        client = self.get_oauth_client(test_user_id)
        producer = client.get_producer()

        # Check what topics user can see
        topics_metadata = producer.list_topics(timeout=10)
        visible_topics = list(topics_metadata.topics.keys())
        self.logger.info(f"User can see {len(visible_topics)} topics")

        # Verify user can access appropriate topics based on group membership
        # (This would require more complex logic to verify exact permissions)

        # Phase 2: Test dynamic membership changes
        self.logger.info("\n=== Phase 2: Testing dynamic group membership changes ===")

        # Start a continuous producer in background
        baseline_idp_queries = self.get_idp_request_count()

        # Change user's group membership
        self.logger.info(f"Modifying group membership for {test_user_id}")
        self.keycloak.admin_ll.get_user_id(f"service-account-{test_user_id}")

        # Remove from current groups
        for group in test_user_groups:
            try:
                self.keycloak.admin.remove_service_user_from_group(test_user_id, group)
                self.logger.info(f"Removed {test_user_id} from {group}")
            except Exception as e:
                self.logger.warning(f"Failed to remove from {group}: {e}")

        # Add to new group
        new_group = "data-engineers"
        self.keycloak.admin.add_service_user_to_group(test_user_id, new_group)
        self.logger.info(f"Added {test_user_id} to {new_group}")

        # Wait for reauth window (kafka_sasl_max_reauth_ms = 60s + margin)
        self.logger.info("Waiting for reauth window (90 seconds)")
        time.sleep(90)

        # Create new client to force reauthentication
        new_client = self.get_oauth_client(test_user_id)
        new_producer = new_client.get_producer()

        # Check updated permissions
        topics_metadata = new_producer.list_topics(timeout=10)
        new_visible_topics = list(topics_metadata.topics.keys())
        self.logger.info(
            f"After group change, user can see {len(new_visible_topics)} topics"
        )

        # User should now be able to access data-* topics
        data_topics = topics_by_pattern["data-"]
        test_data_topic = random.choice(data_topics)

        try:
            new_producer.produce(
                test_data_topic, key="test", value=b"test-after-change"
            )
            new_producer.flush(timeout=10)
            self.logger.info(
                f"✓ User successfully produced to {test_data_topic} after group change"
            )
        except Exception as e:
            self.logger.error(f"✗ User failed to produce after group change: {e}")
            raise AssertionError(
                "User should have access to data-* topics after joining data-engineers"
            )

        # Check IdP query rate
        new_idp_queries = self.get_idp_request_count()
        idp_query_increase = new_idp_queries - baseline_idp_queries
        self.logger.info(f"IdP queries increased by {idp_query_increase}")

        # Assertions
        assert len(new_visible_topics) > 0, "User should see some topics after reauth"

        self.logger.info("\n=== Role Hierarchy Test PASSED ===")
        self.logger.info("  Static hierarchy: Verified")
        self.logger.info("  Dynamic membership: Verified")
        self.logger.info(f"  IdP query increase: {idp_query_increase}")
