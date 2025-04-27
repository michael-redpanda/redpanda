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

#include "cluster/errc.h"
#include "model/panda_link.h"

#include <seastar/util/variant_utils.hh>

#include <algorithm>
#include <variant>

namespace cluster {
using model::panda_link_id;
using model::panda_link_metadata;
using model::panda_link_name;
using model::topic_namespace;

panda_link_table::map_t panda_link_table::all_links() const {
    return _underlying;
}

size_t panda_link_table::size() const { return _underlying.size(); }

void panda_link_table::reset_links(map_t links) {
    _underlying = std::move(links);
}

std::optional<panda_link_metadata>
panda_link_table::find_by_name(std::string_view name) const {
    auto id = find_id_by_name(name);
    if (!id.has_value()) {
        return std::nullopt;
    }

    auto meta = find_by_id(id.value());
    vassert(
      meta.has_value(),
      "Inconsistent name index for {} expected id {}",
      name,
      id.value());

    return meta;
}

std::optional<panda_link_metadata>
panda_link_table::find_by_name(const panda_link_name& name) const {
    return find_by_name(std::string_view(name()));
}

std::optional<panda_link_id>
panda_link_table::find_id_by_name(const panda_link_name& name) const {
    return find_id_by_name(std::string_view(name()));
}

std::optional<panda_link_id>
panda_link_table::find_id_by_name(std::string_view name) const {
    auto it = _name_index.find(name);
    if (it == _name_index.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<panda_link_metadata>
panda_link_table::find_by_id(panda_link_id id) const {
    auto it = _underlying.find(id);
    if (it == _underlying.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::error_code
panda_link_table::upsert_link(panda_link_id id, panda_link_metadata meta) {
    auto it = _name_index.find(std::string_view(meta.name()));
    if (it != _name_index.end()) {
        if (it->second != id) {
            throw std::logic_error(ss::format(
              "panda link meta id={} is attempting to use a name {} which is "
              "already registered to {}",
              id,
              meta.name,
              it->second));
        }
        if (
          meta.config.panda_link_auto_create_topics
          && topic_already_being_mirrored(all_topics_tag{})) {
            return make_error_code(errc::topic_already_being_mirrored);
        } else {
            if (std::ranges::any_of(
                  meta.config.mirrored_topics, [this](const auto& topic) {
                      return topic_already_being_mirrored(topic);
                  })) {
                return make_error_code(errc::topic_already_being_mirrored);
            }
        }
    } else {
        // If there already exists a link that is mirroring all topics, then
        // exit immediately
        if (_topic_index.find(all_topics_tag{}) != _topic_index.end()) {
            return make_error_code(errc::topic_already_being_mirrored);
        }
        // If the new link is set to mirror all topics but there already exists
        // topics being mirrored, then exit immediately
        if (
          meta.config.panda_link_auto_create_topics && !_topic_index.empty()) {
            return make_error_code(errc::topic_already_being_mirrored);
        }
        // Check if any entries in meta.config.mirrored_topics are in
        // _topic_index using ranges
        if (std::ranges::any_of(
              meta.config.mirrored_topics, [this](const auto& topic) {
                  return _topic_index.contains(topic);
              })) {
            return make_error_code(errc::topic_already_being_mirrored);
        }
        _name_index.emplace(meta.name, id);
    }

    if (meta.config.panda_link_auto_create_topics) {
        // If the link is set to mirror all topics, then add an entry to
        // _topic_index with all_topics_tag
        _topic_index.insert({all_topics_tag{}, id});
    } else {
        // Otherwise, add an entry for each topic in
        // meta.config.mirrored_topics
        std::ranges::for_each(
          meta.config.mirrored_topics,
          [this, id](const auto& topic) { _topic_index.emplace(topic, id); });
    }
    _underlying.insert_or_assign(id, std::move(meta));

    return make_error_code(errc::success);
}

void panda_link_table::remove_link(const panda_link_name& name) {
    auto name_it = _name_index.find(std::string_view(name()));
    if (name_it == _name_index.end()) {
        return;
    }
    auto id = name_it->second;
    auto it = _underlying.find(id);
    vassert(
      it != _underlying.end(),
      "inconsistency: name index index had a record with name: {} id: {}",
      name,
      id);
    const auto& meta = it->second;
    // Delete topic index entries
    if (meta.config.panda_link_auto_create_topics) {
        _topic_index.erase(all_topics_tag{});
    } else {
        std::ranges::for_each(
          meta.config.mirrored_topics,
          [this](const auto& topic) { _topic_index.erase(topic); });
    }
    _name_index.erase(name_it);
    _underlying.erase(it);
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

bool panda_link_table::topic_already_being_mirrored(
  const topic_map_entry& entry) const {
    return ss::visit(
      entry,
      [this](const all_topics_tag&) { return !_topic_index.empty(); },
      [this](const topic_namespace& entry) {
          return _topic_index.contains(entry);
      });
}
} // namespace cluster
