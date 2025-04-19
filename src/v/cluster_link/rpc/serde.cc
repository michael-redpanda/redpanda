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

#include "cluster_link/rpc/serde.h"

#include <ostream>

auto fmt::formatter<cluster_link::rpc::panda_link_update_request>::format(
  const cluster_link::rpc::panda_link_update_request& cmd,
  fmt::format_context& ctx) -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(), "panda_link_update_request{{meta: {}}}", cmd.meta);
}

auto fmt::formatter<cluster_link::rpc::panda_link_update_reply>::format(
  const cluster_link::rpc::panda_link_update_reply& cmd,
  fmt::format_context& ctx) -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(), "panda_link_update_reply{{errc: {}}}", cmd.errc);
}

namespace cluster_link::rpc {
panda_link_update_request::panda_link_update_request(
  model::panda_link_metadata m)
  : meta(std::move(m)) {}

panda_link_update_reply::panda_link_update_reply(cluster::errc e)
  : errc(e) {}

std::ostream&
operator<<(std::ostream& os, const panda_link_update_request& cmd) {
    fmt::print(os, "{}", cmd);
    return os;
}

std::ostream& operator<<(std::ostream& os, const panda_link_update_reply& cmd) {
    fmt::print(os, "{}", cmd);
    return os;
}
} // namespace cluster_link::rpc
