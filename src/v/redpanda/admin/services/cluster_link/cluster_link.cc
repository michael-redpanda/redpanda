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

#include "redpanda/admin/services/cluster_link/cluster_link.h"

#include "cluster_link/service.h"
#include "redpanda/admin/services/cluster_link/converter.h"
#include "serde/protobuf/rpc.h"

namespace admin {
namespace {
template<typename T>
T handle_error(cluster_link::result<T> result) {
    if (result.has_value()) {
        return std::move(result).assume_value();
    }
    auto info = result.assume_error();
    switch (info.code()) {
    case cluster_link::errc::success:
        vassert(false, "Unexpected success code in handle_error");
    case cluster_link::errc::invalid_task_state_change:
    case cluster_link::errc::task_not_running:
    case cluster_link::errc::task_already_running:
    case cluster_link::errc::failed_to_start_task:
    case cluster_link::errc::task_already_registered_on_link:
    case cluster_link::errc::task_creation_failed:
    case cluster_link::errc::rpc_error:
        throw serde::pb::rpc::internal_exception(info.message());
    case cluster_link::errc::failed_to_connect_to_remote_cluster:
    case cluster_link::errc::remote_cluster_does_not_support_required_api:
    case cluster_link::errc::link_connection_failed:
    case cluster_link::errc::cluster_link_disabled:
        throw serde::pb::rpc::unavailable_exception(info.message());
    case cluster_link::errc::link_id_not_found:
        throw serde::pb::rpc::not_found_exception(info.message());
    case cluster_link::errc::invalid_configuration:
        throw serde::pb::rpc::invalid_argument_exception(info.message());
    case cluster_link::errc::topic_already_mirrored:
    case cluster_link::errc::topic_mirrored_by_other_link:
    case cluster_link::errc::topic_not_being_mirrored:
        throw serde::pb::rpc::already_exists_exception(info.message());
    }
}
} // namespace

cluster_link_service_impl::cluster_link_service_impl(
  ss::sharded<cluster_link::service>* service)
  : _service(service) {}

ss::future<proto::admin::cluster_link>
cluster_link_service_impl::create_cluster_link(
  proto::admin::create_cluster_link_request req) {
    auto md = convert_create_to_metadata(std::move(req));
    auto resp = handle_error(
      co_await _service->local().create_cluster_link(std::move(md)));

    co_return metadata_to_cluster_link(std::move(resp));
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
