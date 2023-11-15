# Copyright 2023 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

from time import perf_counter
from typing import Optional

from ducktape.mark import parametrize
from rptest.clients.rpk import RpkTool
from rptest.services.admin import Admin
from rptest.services.cluster import cluster
from rptest.services.producer_swarm import ProducerSwarm
from rptest.services.redpanda import SecurityConfig
from rptest.services.rpk_consumer import RpkConsumer
from rptest.tests.redpanda_test import RedpandaTest


class ManyClientsTestAuthzTest(RedpandaTest):
    PRODUCER_COUNT = 4000
    TARGET_THROUGHPUT_MB_S_PER_NODE = 40

    USERNAME = 'user'
    PASSWORD = 'password'
    MECH = 'SCRAM-SHA-256'

    admin = None
    super_rpk = None
    rpk = None

    def __init__(self, *args, **kwargs):
        kwargs['log_level'] = "info"

        kwargs['extra_rp_conf'] = {
            # Enable segment size jitter as this is a stress test and does not
            # rely on exact segment counts.
            'log_segment_size_jitter_percent':
            5,

            # This limit caps the produce throughput to a sustainable rate for a RP
            # cluster that has 384MB of memory per shard. It is set here to
            # since our current backpressure mechanisms will allow producers to
            # produce at a much higher rate and cause RP to run out of memory.
            'kafka_throughput_limit_node_in_bps':
            self.TARGET_THROUGHPUT_MB_S_PER_NODE * 1024 *
            1024,  # 100MiB/s per node

            # Set higher connection count limits than the redpanda default.
            # Factor of 4: allow each client 3 connections (producer,consumer,admin), plus
            # 1 connection to accomodate reconnects while a previous connection is
            # still live.
            'kafka_connections_max':
            self.PRODUCER_COUNT * 4,
            'kafka_connections_max_per_ip':
            self.PRODUCER_COUNT * 4,
        }
        super().__init__(*args, **kwargs)

    def setUp(self):
        pass

    def _setup_auth(self):
        self.admin.create_user(username=self.USERNAME,
                               password=self.PASSWORD,
                               algorithm=self.MECH)
        self.super_rpk.sasl_allow_principal(
            principal=self.USERNAME,
            operations=['all'],
            resource='topic',
            resource_name='*',
            username=self.redpanda.SUPERUSER_CREDENTIALS[0],
            password=self.redpanda.SUPERUSER_CREDENTIALS[1],
            mechanism=self.redpanda.SUPERUSER_CREDENTIALS[2])

        self.super_rpk.sasl_allow_principal(
            principal=self.USERNAME,
            operations=['all'],
            resource='group',
            resource_name='*',
            username=self.redpanda.SUPERUSER_CREDENTIALS[0],
            password=self.redpanda.SUPERUSER_CREDENTIALS[1],
            mechanism=self.redpanda.SUPERUSER_CREDENTIALS[2])

    def get_rpk_credentials(self, username: str, password: str,
                            mechanism: str) -> RpkTool:
        """Creates an RpkTool with username & password
        """
        return RpkTool(self.redpanda,
                       username=username,
                       password=password,
                       sasl_mechanism=mechanism)

    def get_super_rpk(self, security_enabled: bool) -> RpkTool:
        if security_enabled:
            return self.get_rpk_credentials(
                username=self.redpanda.SUPERUSER_CREDENTIALS[0],
                password=self.redpanda.SUPERUSER_CREDENTIALS[1],
                mechanism=self.redpanda.SUPERUSER_CREDENTIALS[2])
        else:
            return RpkTool(self.redpanda)

    def get_rpk(self, security_enabled: bool) -> RpkTool:
        if security_enabled:
            return self.get_rpk_credentials(username=self.USERNAME,
                                            password=self.PASSWORD,
                                            mechanism=self.MECH)
        else:
            return RpkTool(self.redpanda)

    def get_rpk_consumer(self, topic_name: str, group_name: str,
                         security_enabled: bool) -> RpkConsumer:
        if security_enabled:
            return RpkConsumer(self.test_context,
                               self.redpanda,
                               topic_name,
                               group=group_name,
                               save_msgs=False,
                               username=self.USERNAME,
                               password=self.PASSWORD,
                               mechanism=self.MECH)
        else:
            return RpkConsumer(self.test_context,
                               self.redpanda,
                               topic_name,
                               group=group_name,
                               save_msgs=False)

    def setup_cluster(self, enable_auth: bool):
        if enable_auth:
            security_config = SecurityConfig()
            security_config.enable_sasl = True
            security_config.kafka_enable_authorization = True
            security_config.endpoint_authn_method = 'sasl'
            self.redpanda.set_security_settings(security_config)

        super().setUp()

        self.admin = Admin(self.redpanda)
        self.super_rpk = self.get_super_rpk(enable_auth)
        self.rpk = self.get_rpk(enable_auth)

        if enable_auth:
            self._setup_auth()

    @cluster(num_nodes=7)
    @parametrize(enable_auth=True)
    @parametrize(enable_auth=False)
    def test_many_clients(self, enable_auth: bool):
        assert not self.debug_mode

        self.setup_cluster(enable_auth=enable_auth)

        partition_count = 100

        PRODUCER_TIMEOUT_MS = 5000
        TOPIC_NAME = "manyclients"

        # Realistic conditions: 128MB is the segment size in the cloud
        segment_size = 128 * 1024 * 1024
        retention_size = 8 * segment_size

        self.super_rpk.create_topic(topic=TOPIC_NAME,
                                    partitions=partition_count,
                                    config={
                                        'retention.bytes': retention_size,
                                        'segment.bytes': segment_size
                                    })

        consumer_a = self.get_rpk_consumer(TOPIC_NAME, "testgroup",
                                           enable_auth)
        consumer_b = self.get_rpk_consumer(TOPIC_NAME, "testgroup",
                                           enable_auth)
        consumer_c = self.get_rpk_consumer(TOPIC_NAME, "testgroup",
                                           enable_auth)

        target_throughput_mb_s = self.TARGET_THROUGHPUT_MB_S_PER_NODE * len(
            self.redpanda.nodes)
        min_record_size = 0
        max_record_size = 16384
        producer_kwargs = {}
        producer_kwargs['min_record_size'] = min_record_size
        producer_kwargs['max_record_size'] = max_record_size

        effective_msg_size = min_record_size + (max_record_size -
                                                min_record_size) // 2

        self.logger.info(
            f"Using mean message size {effective_msg_size} ({producer_kwargs['min_record_size']}-{producer_kwargs['max_record_size']})"
        )

        msg_rate = (target_throughput_mb_s * 1024 * 1024) // effective_msg_size
        message_per_sec_per_producer = msg_rate // self.PRODUCER_COUNT
        producer_kwargs[
            'messages_per_second_per_producer'] = message_per_sec_per_producer

        assert message_per_sec_per_producer > 0, "Bad sizing params, need at least Mps"

        target_runtime_s = 30
        records_per_producer = message_per_sec_per_producer * target_runtime_s
        self.logger.info(
            f"{self.PRODUCER_COUNT} producers writing {message_per_sec_per_producer} msg/s each, {records_per_producer} records each"
        )

        if enable_auth:
            producer_kwargs['properties'] = {
                'sasl.username': self.USERNAME,
                'sasl.password': self.PASSWORD,
                'sasl.mechanism': self.MECH,
                'security.protocol': 'SASL_PLAINTEXT'
            }

        producer = ProducerSwarm(context=self.test_context,
                                 redpanda=self.redpanda,
                                 topic=TOPIC_NAME,
                                 producers=self.PRODUCER_COUNT,
                                 records_per_producer=records_per_producer,
                                 timeout_ms=PRODUCER_TIMEOUT_MS,
                                 **producer_kwargs)
        start_time = perf_counter()
        producer.start()
        consumer_a.start()
        consumer_b.start()
        consumer_c.start()

        producer.wait()
        producer_end = perf_counter()

        expect = self.PRODUCER_COUNT * records_per_producer

        def complete():
            self.logger.info(
                f"Message counts: {consumer_a.message_count} {consumer_b.message_count} {consumer_c.message_count} (vs {expect})"
            )
            return consumer_a.message_count + consumer_b.message_count + consumer_c.message_count >= expect

        self.redpanda.wait_until(complete,
                                 timeout_sec=60,
                                 backoff_sec=1,
                                 err_msg="Consumers didn't see all messages")
        
        test_end = perf_counter()

        self.logger.info(f'Producer took {producer_end-start_time}s to complete')
        self.logger.info(f'Consumers took {test_end-producer_end}s to complete after producers')
        self.logger.info(f'Full test took {test_end-start_time}s to complete')