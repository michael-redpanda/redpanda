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

#include "cluster/panda_link/types.h"

#include <seastar/util/variant_utils.hh>

auto fmt::formatter<panda_link::scram_credentials>::format(
  const panda_link::scram_credentials& c,
  format_context& ctx) -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{username={}, password=****, mechanism={}}}",
      c.username,
      c.mechanism);
}

auto fmt::formatter<
  std::optional<panda_link::connection_config::authn_variant>>::
  format(
    const std::optional<panda_link::connection_config::authn_variant>& m,
    format_context& ctx) -> decltype(ctx.out()) {
    if (!m) {
        return fmt::format_to(ctx.out(), "none");
    }
    return ss::visit(*m, [&ctx](const auto& authn) {
        return fmt::format_to(ctx.out(), "{}", authn);
    });
}

auto fmt::formatter<panda_link::connection_config>::format(
  const panda_link::connection_config& c,
  format_context& ctx) -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{bootstrap_servers={}, authn_config={}, cert_file_path={}, "
      "key_file_path={}, ca_file_path={}}}",
      c.bootstrap_servers,
      c.authn_config,
      c.cert_file_path,
      c.key_file_path,
      c.ca_file_path);
}

auto fmt::formatter<panda_link::metadata>::format(
  const panda_link::metadata& m, format_context& ctx) -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{name={}, uuid={}, connection={}, paused={}}}",
      m.name,
      m.uuid,
      m.connection,
      m.paused);
}
