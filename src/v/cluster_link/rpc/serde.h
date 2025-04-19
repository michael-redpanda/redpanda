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

#include "cluster/errc.h"
#include "model/panda_link.h"
#include "serde/envelope.h"

#include <fmt/core.h>

namespace cluster_link::rpc {

struct panda_link_update_request
  : serde::envelope<
      panda_link_update_request,
      serde::version<0>,
      serde::compat_version<0>> {
    using rpc_adl_exempt = std::true_type;

    panda_link_update_request() = default;
    explicit panda_link_update_request(model::panda_link_metadata);

    auto serde_fields() { return std::tie(meta); }

    friend std::ostream&
    operator<<(std::ostream&, const panda_link_update_request&);

    model::panda_link_metadata meta;
};

struct panda_link_update_reply
  : serde::envelope<
      panda_link_update_reply,
      serde::version<0>,
      serde::compat_version<0>> {
    using rpc_adl_exempt = std::true_type;

    panda_link_update_reply() = default;
    explicit panda_link_update_reply(cluster::errc);

    auto serde_fields() { return std::tie(errc); }
    friend std::ostream&
    operator<<(std::ostream&, const panda_link_update_reply&);
    cluster::errc errc{cluster::errc::success};
};
} // namespace cluster_link::rpc

template<>
struct fmt::formatter<cluster_link::rpc::panda_link_update_request>
  : fmt::formatter<string_view> {
    auto format(
      const cluster_link::rpc::panda_link_update_request& cmd,
      format_context& ctx) -> decltype(ctx.out());
};

template<>
struct fmt::formatter<cluster_link::rpc::panda_link_update_reply>
  : fmt::formatter<string_view> {
    auto format(
      const cluster_link::rpc::panda_link_update_reply& cmd,
      format_context& ctx) -> decltype(ctx.out());
};
