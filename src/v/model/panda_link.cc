/*
 * Copyright 2025 Redpanda Data, Inc.
 *
 * Licensed as a Redpanda Enterprise file under the Redpanda Community
 * License (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://github.com/redpanda-data/redpanda/blob/master/licenses/rcl.md
 */

#include "model/panda_link.h"

#include <fmt/ranges.h>

#include <ostream>

auto fmt::formatter<model::panda_link_config>::format(
  const model::panda_link_config& pl,
  fmt::format_context& ctx) -> decltype(ctx.out()) {
    fmt::format_to(
      ctx.out(),
      "{{auto_create_topics: {}, mirrored_topics: {}}}",
      pl.panda_link_auto_create_topics,
      pl.mirrored_topics);
    return ctx.out();
}

auto fmt::formatter<model::panda_link_connection>::format(
  const model::panda_link_connection& pl,
  fmt::format_context& ctx) -> decltype(ctx.out()) {
    fmt::format_to(
      ctx.out(), "{{source_bootstrap_server: {}}}", pl.source_bootstrap_server);
    return ctx.out();
}

auto fmt::formatter<model::panda_link_metadata>::format(
  const model::panda_link_metadata& pl,
  fmt::format_context& ctx) -> decltype(ctx.out()) {
    fmt::format_to(
      ctx.out(),
      "{{name: {}, connection: {}, config: {}}}",
      pl.name,
      pl.connection,
      pl.config);
    return ctx.out();
}

namespace model {
std::ostream& operator<<(std::ostream& os, const panda_link_config& pl) {
    fmt::print(os, "{}", pl);
    return os;
}
std::ostream& operator<<(std::ostream& os, const panda_link_connection& pl) {
    fmt::print(os, "{}", pl);
    return os;
}
std::ostream&
operator<<(std::ostream& os, const model::panda_link_metadata& pl) {
    fmt::print(os, "{}", pl);
    return os;
}
} // namespace model
