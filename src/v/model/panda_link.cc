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

#include "model/panda_link.h"

#include <fmt/ranges.h>

auto fmt::formatter<model::panda_link_metadata>::format(
  const model::panda_link_metadata& m,
  format_context& ctx) -> decltype(ctx.out()) {
    auto out = ctx.out();
    fmt::format_to(
      out,
      "{{name: \"{}\", source_cluster_bootstrap_server: "
      "{}}}",
      m.name,
      m.source_cluster_bootstrap_server);
    return out;
}

namespace model {

std::ostream& operator<<(std::ostream& os, const panda_link_metadata& m) {
    fmt::print(os, "{}", m);
    return os;
}
} // namespace model
