# Copyright 2023 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

from functools import partial
import json

from rptest.clients.rpk import RpkTool
from rptest.services.admin import Admin
from rptest.services.cluster import cluster
from rptest.services.producer_swarm import ProducerSwarm
from rptest.services.redpanda import LoggingConfig, ResourceSettings
from rptest.services.rpk_consumer import RpkConsumer
from rptest.tests.redpanda_test import RedpandaTest
from rptest.util import wait_until
from rptest.utils.audit_log import AuditLogConfig, AuditLogTestSecurityConfig, aggregate_count, ocsf_message_match


class AuditLogScaleTest(RedpandaTest):
    """Scale test for the audit log feature
    """

    username = 'test-user'
    password = 'test-user-pw'
    mech = 'SCRAM-SHA-256'
    audit_topic_name = "__audit_log"

    audit_consumer_username = 'audit-consumer'
    audit_consumer_password = 'audit-consumer-pw'
    audit_consumer_mech = 'SCRAM-SHA-256'

    group_name = 'testgroup'

    producer_count = 4000

    target_throughput_mb_s_per_node = 40

    def __init__(self, test_context):
        self.audit_log_config = AuditLogConfig(enabled=True,
                                               event_types=[
                                                   'management', 'produce',
                                                   'consume', 'describe',
                                                   'heartbeat', 'authenticate'
                                               ])

        self.security_config = AuditLogTestSecurityConfig(
            user_creds=[self.username, self.password, self.mech])

        self.extra_rp_conf = self.audit_log_config.to_conf()

        self.extra_rp_conf['kafka_connections_max'] = self.producer_count * 4
        self.extra_rp_conf[
            'kafka_connections_max_per_ip'] = self.producer_count * 4
        self.extra_rp_conf[
            'kafka_throughput_limit_node_in_bps'] = self.target_throughput_mb_s_per_node * 1024 * 1024
        self.extra_rp_conf['log_segment_size_jitter_percent'] = 5

        super(AuditLogScaleTest, self).__init__(
            test_context=test_context,
            extra_rp_conf=self.extra_rp_conf,
            security=self.security_config,
            log_config=LoggingConfig('info',
                                     logger_levels={'auditing': 'trace'}))

    def setUp(self):
        pass

    def get_rpk_credentials(self, username: str, password: str,
                            mech: str) -> RpkTool:
        return RpkTool(self.redpanda,
                       username=username,
                       password=password,
                       sasl_mechanism=mech)

    def get_rpk(self):
        return self.get_rpk_credentials(self.username, self.password,
                                        self.mech)

    def get_super_rpk(self):
        return self.get_rpk_credentials(self.redpanda.SUPERUSER_CREDENTIALS[0],
                                        self.redpanda.SUPERUSER_CREDENTIALS[1],
                                        self.redpanda.SUPERUSER_CREDENTIALS[2])

    def get_rpk_consumer(self, topic, offset, username, password,
                         mech) -> RpkConsumer:
        return RpkConsumer(self.test_context,
                           self.redpanda,
                           topic,
                           offset=offset,
                           username=username,
                           password=password,
                           mechanism=mech)

    def read_all_from_audit_log(self,
                                filter_fn,
                                stop_cond,
                                start_offset: str = 'oldest',
                                timeout_sec: int = 30,
                                backoff_sec: int = 1):
        """Reads all messages from the audit log
        
        Parameters
        ----------
        filter_fn:
            The function used to filter messages.  Last argument must accept
            a list of records
            
        stop_cond:
            The function to use to check to stop.  Last argument must accept
            a list of records
        
        start_offset: str, default='oldest'
            Starting offset for the consumer
            
        timeout_sec: int, default=30,
            How long to wait
            
        backoff_sec: int, default=1
            Backoff
            
        consumer: Optional[RpkTool], default=None
            The consumer to use, or None if to use a new one
        
        Returns
        -------
        [str]
            List of records as json objects
        """
        class MessageMapper():
            def __init__(self, logger, filter_fn, stop_cond):
                self.logger = logger
                self.records = []
                self.filter_fn = filter_fn
                self.stop_cond = stop_cond
                self.next_offset_ingest = 0

            def ingest(self, records):
                new_records = records[self.next_offset_ingest:]
                self.next_offset_ingest = len(records)
                new_records = [json.loads(msg['value']) for msg in new_records]
                self.logger.debug(f'Ingested records:')
                for rec in new_records:
                    self.logger.debug(f'{rec}')
                self.logger.debug(f"Ingested: {len(new_records)} records")
                self.records += [
                    r for r in new_records if self.filter_fn(record=r)
                ]

            def is_finished(self):
                return stop_cond(self.records)

        mapper = MessageMapper(self.redpanda.logger, filter_fn, stop_cond)
        consumer = self.get_rpk_consumer(topic=self.audit_topic_name,
                                         offset=start_offset,
                                         username=self.audit_consumer_username,
                                         password=self.audit_consumer_password,
                                         mech=self.audit_consumer_mech)
        consumer.start()

        def predicate():
            mapper.ingest(consumer.messages)
            return mapper.is_finished()

        wait_until(predicate, timeout_sec=timeout_sec, backoff_sec=backoff_sec)
        consumer.stop()
        consumer.free()
        return mapper.records

    @cluster(num_nodes=8)
    def test_many_same_clients_regular_environment(self):
        self._test_many_same_clients(False)

    @cluster(num_nodes=8)
    def test_may_same_clients_constrainted_environment(self):
        self._test_many_same_clients(True)

    def _test_many_same_clients(self, use_constrained_env: bool):

        assert not self.debug_mode

        if use_constrained_env:
            num_cpus = 2
            memory_mb = 768

            resource_settings = ResourceSettings(num_cpus=num_cpus,
                                                 memory_mb=memory_mb)
            self.redpanda.set_resource_settings(resource_settings)

        super().setUp()

        partition_count = 100
        producer_timeout_ms = 5000
        topic_name = "auditabletopic"

        segment_size = 128 * 1024 * 1024
        retention_size = 8 * segment_size

        admin = Admin(self.redpanda)

        admin.create_user(self.username, self.password, self.mech)
        admin.create_user(self.audit_consumer_username,
                          self.audit_consumer_password,
                          self.audit_consumer_mech)

        super_rpk = self.get_super_rpk()

        super_rpk.sasl_allow_principal(
            principal=self.audit_consumer_username,
            operations=['describe', 'read'],
            resource='topic',
            resource_name=self.audit_topic_name,
            username=self.redpanda.SUPERUSER_CREDENTIALS[0],
            password=self.redpanda.SUPERUSER_CREDENTIALS[1],
            mechanism=self.redpanda.SUPERUSER_CREDENTIALS[2])

        super_rpk.sasl_allow_principal(
            principal=self.username,
            operations=['all'],
            resource='topic',
            resource_name=topic_name,
            username=self.redpanda.SUPERUSER_CREDENTIALS[0],
            password=self.redpanda.SUPERUSER_CREDENTIALS[1],
            mechanism=self.redpanda.SUPERUSER_CREDENTIALS[2])

        super_rpk.sasl_allow_principal(
            principal=self.username,
            operations=['all'],
            resource='group',
            resource_name=self.group_name,
            username=self.redpanda.SUPERUSER_CREDENTIALS[0],
            password=self.redpanda.SUPERUSER_CREDENTIALS[1],
            mechanism=self.redpanda.SUPERUSER_CREDENTIALS[2])

        self.get_rpk_credentials(self.username, self.password,
                                 self.mech).create_topic(
                                     topic=topic_name,
                                     partitions=partition_count,
                                     config={
                                         'retention.bytes': retention_size,
                                         'segment.bytes': segment_size
                                     })

        consumer_a = RpkConsumer(self.test_context,
                                 self.redpanda,
                                 topic_name,
                                 group=self.group_name,
                                 save_msgs=False,
                                 username=self.username,
                                 password=self.password,
                                 mechanism=self.mech)

        consumer_b = RpkConsumer(self.test_context,
                                 self.redpanda,
                                 topic_name,
                                 group=self.group_name,
                                 save_msgs=False,
                                 username=self.username,
                                 password=self.password,
                                 mechanism=self.mech)

        consumer_c = RpkConsumer(self.test_context,
                                 self.redpanda,
                                 topic_name,
                                 group=self.group_name,
                                 save_msgs=False,
                                 username=self.username,
                                 password=self.password,
                                 mechanism=self.mech)

        target_throughput_mb_s = self.target_throughput_mb_s_per_node * len(
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
        message_per_sec_per_producer = msg_rate // self.producer_count
        producer_kwargs[
            'messages_per_second_per_producer'] = message_per_sec_per_producer

        assert message_per_sec_per_producer > 0, "Bad sizing params, need at least Mps"

        target_runtime_s = 30
        records_per_producer = message_per_sec_per_producer * target_runtime_s
        self.logger.info(
            f"{self.producer_count} producers writing {message_per_sec_per_producer} msg/s each, {records_per_producer} records each"
        )

        properties = {}
        properties['sasl.username'] = self.username
        properties['sasl.password'] = self.password
        properties['sasl.mechanism'] = self.mech
        properties['security.protocol'] = 'SASL_PLAINTEXT'

        producer_kwargs['properties'] = properties

        producer = ProducerSwarm(context=self.test_context,
                                 redpanda=self.redpanda,
                                 topic=topic_name,
                                 producers=self.producer_count,
                                 records_per_producer=records_per_producer,
                                 timeout_ms=producer_timeout_ms,
                                 **producer_kwargs)

        producer.start()
        consumer_a.start()
        consumer_b.start()
        consumer_c.start()

        producer.wait()

        expect = self.producer_count * records_per_producer

        def complete():
            self.logger.info(
                f"Message counts: {consumer_a.message_count} {consumer_b.message_count} {consumer_c.message_count} (vs {expect})"
            )
            return consumer_a.message_count + consumer_b.message_count + consumer_c.message_count >= expect

        self.redpanda.wait_until(complete,
                                 timeout_sec=30,
                                 backoff_sec=1,
                                 err_msg="Consumers didn't see all messages")

        match_kwargs = {}
        match_kwargs['service_name'] = "kafka rpc protocol"
        match_kwargs['api_operation'] = "produce"
        match_kwargs['resource_entry'] = {"name": topic_name, "type": "topic"}
        match_kwargs['principal'] = self.username

        records = self.read_all_from_audit_log(
            lambda record: ocsf_message_match(
                class_uid=6003, record=record, **match_kwargs),
            lambda records: aggregate_count(records) >= expect)

        assert aggregate_count(
            records
        ) == expect, f"Invalid number of produce records, expected {expect} got {aggregate_count(records)}"
