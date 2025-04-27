/*
 * Copyright 2025 Redpanda Data, Inc.
 *
 * Licensed as a Redpanda Enterprise file under the Redpanda Community
 * License (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://github.com/redpanda-data/redpanda/blob/master/licenses/rcl.md
 */

#include "cluster/panda_link_table.h"

#include "model/panda_link.h"

#include <seastar/util/variant_utils.hh>

namespace cluster {
using model::panda_link_id;
using model::panda_link_name;
using model::topic_namespace;

panda_link_table::map_t panda_link_table::all_links() const {
    return _underlying;
}

size_t panda_link_table::size() const { return _underlying.size(); }

void panda_link_table::reset_links(map_t links) {
    _underlying = std::move(links);
}

bool panda_link_table::name_less_cmp::operator()(
  const panda_link_name& lhs, const panda_link_name& rhs) const {
    return lhs < rhs;
}

bool panda_link_table::name_less_cmp::operator()(
  const panda_link_name& lhs, const std::string_view& rhs) const {
    return lhs() < rhs;
}

bool panda_link_table::name_less_cmp::operator()(
  const std::string_view& lhs, const panda_link_name& rhs) const {
    return lhs < rhs();
}

bool panda_link_table::topic_map_less_cmp::operator()(
  const topic_map_entry& lhs, const topic_map_entry& rhs) const {
    return ss::visit(
      lhs,
      [](const all_topics_tag&) { return true; },
      [&rhs](const topic_namespace& lhs) {
          return ss::visit(
            rhs,
            [](const all_topics_tag&) { return false; },
            [&lhs](const topic_namespace& rhs) { return lhs < rhs; });
      });
}
} // namespace cluster
