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

#pragma once

#include "proto/redpanda/core/admin/cluster_link.proto.h"

namespace admin {
class cluster_link_service_impl : public proto::admin::cluster_link_service {
public:
    cluster_link_service_impl() = default;

    ss::future<proto::admin::cluster_link>
      create_cluster_link(proto::admin::create_cluster_link_request) override;

    ss::future<proto::admin::delete_cluster_link_response>
      delete_cluster_link(proto::admin::delete_cluster_link_request) override;

    ss::future<proto::admin::cluster_link>
      get_cluster_link(proto::admin::get_cluster_link_request) override;

    ss::future<proto::admin::list_cluster_links_response>
      list_cluster_links(proto::admin::list_cluster_links_request) override;

    ss::future<proto::admin::cluster_link>
      update_cluster_link(proto::admin::update_cluster_link_request) override;

    ss::future<proto::admin::cluster_link>
      fail_over(proto::admin::fail_over_request) override;
};
} // namespace admin
