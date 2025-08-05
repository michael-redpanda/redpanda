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

#include "redpanda/admin/services/cluster_link.h"

#include "serde/protobuf/rpc.h"

namespace admin {
ss::future<proto::admin::cluster_link>
cluster_link_service_impl::create_cluster_link(
  proto::admin::create_cluster_link_request) {
    throw serde::pb::rpc::unimplemented_exception();
}

ss::future<proto::admin::delete_cluster_link_response>
cluster_link_service_impl::delete_cluster_link(
  proto::admin::delete_cluster_link_request) {
    throw serde::pb::rpc::unimplemented_exception();
}

ss::future<proto::admin::cluster_link>
cluster_link_service_impl::get_cluster_link(
  proto::admin::get_cluster_link_request) {
    throw serde::pb::rpc::unimplemented_exception();
}

ss::future<proto::admin::list_cluster_links_response>
cluster_link_service_impl::list_cluster_links(
  proto::admin::list_cluster_links_request) {
    throw serde::pb::rpc::unimplemented_exception();
}

ss::future<proto::admin::cluster_link>
cluster_link_service_impl::update_cluster_link(
  proto::admin::update_cluster_link_request) {
    throw serde::pb::rpc::unimplemented_exception();
}

ss::future<proto::admin::cluster_link>
cluster_link_service_impl::fail_over(proto::admin::fail_over_request) {
    throw serde::pb::rpc::unimplemented_exception();
}
} // namespace admin
