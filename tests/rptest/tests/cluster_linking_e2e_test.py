# Copyright 2025 Redpanda Data, Inc.
#
# Use of this software is governed by the Business Source License
# included in the file licenses/BSL.md
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0

from ducktape.mark import matrix

from connectrpc.errors import ConnectError, ConnectErrorCode
from google.protobuf import duration_pb2

from rptest.clients.admin.v2 import Admin as AdminV2
from rptest.clients.admin.proto.redpanda.core.admin import admin_pb2, admin_pb2_connect, shadow_link_pb2, shadow_link_pb2_connect
from rptest.services.cluster import cluster
from rptest.services.multi_cluster_services import Cluster, MultiClusterServices, ServiceType
from rptest.services.redpanda import LoggingConfig
from rptest.tests.redpanda_test import RedpandaTest
from rptest.util import expect_exception, wait_until_result


class MultiClusterTestBase(RedpandaTest):
    def __init__(self, test_context, *args, **kwargs):
        super().__init__(test_context=test_context, *args, **kwargs)

    def basic_ops(self, services: MultiClusterServices):
        def at_least_one_topic_exists(services: MultiClusterServices,
                                      node: Cluster):
            topics = services.list_topics(node, detailed=True)
            return len(topics) > 0, topics

        topic = 'test-topic'
        services.create_topic(services.primary,
                              topic,
                              partitions=3,
                              replicas=3)
        p_topics = wait_until_result(
            lambda: at_least_one_topic_exists(services, services.primary),
            timeout_sec=30,
            err_msg="Failed to create a single topic on the primary cluster")

        services.create_topic(services.secondary,
                              topic,
                              partitions=3,
                              replicas=3)
        s_topics = wait_until_result(
            lambda: at_least_one_topic_exists(services, services.secondary),
            timeout_sec=30,
            err_msg="Failed to create a single topic on the secondary cluster")

        assert p_topics == s_topics, \
            f"Expected same topics on both clusters, got {p_topics=} vs {s_topics=}"

        assert len(p_topics) == 1 and p_topics[0][0] == topic,\
            f"Expected {topic=}, got {p_topics=}"

        status_json = services.primary.admin.get_status_ready()
        assert status_json['status'] == 'ready', \
                f"Expected ready, got {status_json=}"

        if services.secondary.is_redpanda:
            status_json = services.secondary.admin.get_status_ready()
            assert status_json['status'] == 'ready', \
                f"Expected ready, got {status_json=}"
        else:
            with expect_exception(NotImplementedError, lambda e: True):
                services.secondary.admin.get_status_ready()


class MultiClusterRedpandaTest(MultiClusterTestBase):
    """
    Just verifies MultiClusterServices for now. rp + rp & rp + kafka
    """
    def __init__(self, test_context, *args, **kwargs):
        super().__init__(test_context=test_context,
                         num_brokers=3,
                         *args,
                         **kwargs)

        self.test_context = test_context

    def setUp(self):
        # MultiClusterServices will set itself up
        pass

    @cluster(num_nodes=6)
    def test_basic_ops(self):
        with MultiClusterServices(self.test_context,
                                  self.logger,
                                  self.redpanda,
                                  secondary_type=ServiceType.REDPANDA,
                                  num_brokers=3) as services:
            assert services.secondary.is_redpanda, \
                f"Expected Redpanda service, got {services.secondary}"
            self.basic_ops(services)


class MultiClusterKafkaTest(MultiClusterTestBase):
    """
    Just verifies MultiClusterServices for now. rp + rp & rp + kafka
    """
    def __init__(self, test_context, *args, **kwargs):
        super().__init__(test_context=test_context,
                         num_brokers=3,
                         *args,
                         **kwargs)

        self.test_context = test_context

    def setUp(self):
        # MultiClusterServices will set itself up
        pass

    @cluster(num_nodes=7)
    def test_basic_ops(self):
        with MultiClusterServices(self.test_context,
                                  self.logger,
                                  self.redpanda,
                                  secondary_type=ServiceType.KAFKA,
                                  num_brokers=3) as services:
            assert services.secondary.is_kafka, \
                f"Expected Kafka service, got {services.secondary}"
            self.basic_ops(services)


class ShadowLinkBasicTests(RedpandaTest):
    def __init__(self, test_context, *args, **kwargs):
        super().__init__(test_context=test_context,
                         num_brokers=3,
                         log_config=LoggingConfig(
                             'info', logger_levels={'cluster_link': 'trace'}),
                         *args,
                         **kwargs)

        self.test_context = test_context
        self.admin_v2: AdminV2 = None
        self.services: MultiClusterServices = None

    def setUp(self):
        self.services = MultiClusterServices(
            self.test_context,
            self.logger,
            self.redpanda,
            secondary_type=ServiceType.REDPANDA,
            num_brokers=3)
        self.services.setUp()
        self.services.primary.service.enable_development_feature_support()
        self.services.primary.service.set_cluster_config(
            values={"development_enable_cluster_link": True})
        self.admin_v2 = AdminV2(self.services.primary.service)

    def list_all_shadow_links(
        self, client: shadow_link_pb2_connect.ShadowLinkServiceClient
    ) -> list[shadow_link_pb2.ShadowLink]:
        resp = client.call_list_shadow_links(
            req=shadow_link_pb2.ListShadowLinksRequest())
        if resp.error() is not None:
            raise resp.error()
        return [link for link in resp.message().shadow_links]

    def get_shadow_link(
            self, client: shadow_link_pb2_connect.ShadowLinkServiceClient,
            name: str) -> shadow_link_pb2.ShadowLink:
        resp = client.call_get_shadow_link(
            req=shadow_link_pb2.GetShadowLinkRequest(name=name))
        if resp.error() is not None:
            raise resp.error()
        return resp.message().shadow_link

    @cluster(num_nodes=6)
    def test_service_exists(self):
        admin: admin_pb2_connect.AdminServiceClient = self.admin_v2.admin()
        rpc_routes: admin_pb2.ListRPCRoutesResponse = admin.call_list_rpc_routes(
            req=admin_pb2.ListRPCRoutesRequest()).message()
        self.logger.info(f'Routes: {rpc_routes.routes}')

        expected_routes: list[admin_pb2.RPCRoute] = [
            admin_pb2.RPCRoute(
                name="redpanda.core.admin.ShadowLinkService.CreateShadowLink",
                http_route=
                "/v2/redpanda.core.admin.ShadowLinkService/CreateShadowLink"),
            admin_pb2.RPCRoute(
                name="redpanda.core.admin.ShadowLinkService.DeleteShadowLink",
                http_route=
                "/v2/redpanda.core.admin.ShadowLinkService/DeleteShadowLink"),
            admin_pb2.RPCRoute(
                name="redpanda.core.admin.ShadowLinkService.GetShadowLink",
                http_route=
                "/v2/redpanda.core.admin.ShadowLinkService/GetShadowLink"),
            admin_pb2.RPCRoute(
                name="redpanda.core.admin.ShadowLinkService.ListShadowLinks",
                http_route=
                "/v2/redpanda.core.admin.ShadowLinkService/ListShadowLinks"),
            admin_pb2.RPCRoute(
                name="redpanda.core.admin.ShadowLinkService.UpdateShadowLink",
                http_route=
                "/v2/redpanda.core.admin.ShadowLinkService/UpdateShadowLink"),
            admin_pb2.RPCRoute(
                name="redpanda.core.admin.ShadowLinkService.FailOver",
                http_route="/v2/redpanda.core.admin.ShadowLinkService/FailOver"
            ),
        ]

        # Check that all expected routes are present in the actual routes
        actual_routes = list(rpc_routes.routes)
        for expected in expected_routes:
            assert expected in actual_routes, f"Expected route {expected} not found in {actual_routes}"

    @cluster(num_nodes=6)
    def test_create_simple_link(self):
        shadow_link: shadow_link_pb2_connect.ShadowLinkServiceClient = self.admin_v2.shadow_link(
        )
        create_shadow_link_request = shadow_link_pb2.CreateShadowLinkRequest()
        shadow_link_resource = shadow_link_pb2.ShadowLink()
        self.services.secondary.service.nodes
        shadow_link_resource.name = "test-link"
        client_options = shadow_link_pb2.ShadowLinkClientOptions(
            bootstrap_servers=[
                f"{node.name}:9092"
                for node in self.services.secondary.service.nodes
            ])
        self.logger.debug(
            f'Bootstrap servers: {client_options.bootstrap_servers}')

        shadow_link_configurations = shadow_link_pb2.ShadowLinkConfigurations(
            client_options=client_options)
        shadow_link_resource.configurations.CopyFrom(
            shadow_link_configurations)
        create_shadow_link_request.shadow_link.CopyFrom(shadow_link_resource)

        shadow_link_create_result = shadow_link.call_create_shadow_link(
            req=create_shadow_link_request)
        if shadow_link_create_result.error() is not None:
            assert False, f"Failed to create link: {shadow_link_create_result.error()}"
        self.logger.info(
            f'Create shadow link result: {shadow_link_create_result.message().shadow_link}'
        )

        created_shadow_link: shadow_link_pb2.ShadowLink = shadow_link_create_result.message(
        ).shadow_link

        assert created_shadow_link.name == "test-link", \
            f"Expected shadow link name to be 'test-link', but got {created_shadow_link.name}"

        assert created_shadow_link.configurations.topic_metadata_sync_options.interval == duration_pb2.Duration(seconds=0), \
            f"Expected interval to be '0' but got {created_shadow_link.configurations.topic_metadata_sync_options.interval}"

        shadow_links = self.list_all_shadow_links(client=shadow_link)
        assert len(
            shadow_links
        ) == 1, f"Expected exactly one shadow link, got {len(shadow_links)}"
        assert shadow_links[
            0].name == "test-link", f"Expected shadow link name to be 'test-link', got {shadow_links[0].name}"

        got_link = self.get_shadow_link(client=shadow_link, name="test-link")
        assert got_link.name == "test-link", f"Expected shadow link name to be 'test-link', got {got_link.name}"

        try:
            self.get_shadow_link(client=shadow_link, name="non-existent-link")
            assert False, "Should not have gotten a non-existant link"
        except ConnectError as e:
            assert e.code == ConnectErrorCode.NOT_FOUND, f"Expected NOT_FOUND error code, got {e.code}"
