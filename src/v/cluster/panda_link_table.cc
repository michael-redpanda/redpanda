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

#include "cluster/panda_link_table.h"

namespace cluster {

using model::panda_link_id;
using model::panda_link_metadata;
using model::panda_link_name;

panda_link_table::map_t panda_link_table::all_links() const {
    map_t all;
    for (const auto& entry : _underlying) {
        all.emplace(entry.first, entry.second);
    }
    return all;
}

size_t panda_link_table::size() const { return _underlying.size(); }

std::optional<panda_link_metadata>
panda_link_table::find_by_name(const panda_link_name& name) const {
    return find_by_name(std::string_view(name()));
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

std::optional<panda_link_id>
panda_link_table::find_id_by_name(std::string_view name) const {
    auto it = _name_index.find(name);
    if (it == _name_index.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::optional<panda_link_id>
panda_link_table::find_id_by_name(const panda_link_name& name) const {
    return find_id_by_name(std::string_view(name()));
}
std::optional<panda_link_metadata>
panda_link_table::find_by_id(panda_link_id id) const {
    auto it = _underlying.find(id);
    if (it == _underlying.end()) {
        return std::nullopt;
    }
    return it->second;
}

void panda_link_table::upsert_link(panda_link_metadata meta) {
    auto it = _name_index.find(std::string_view(meta.name()));
    if (it != _name_index.end()) {
        if (it->second != meta.uuid) {
            throw std::logic_error(ss::format(
              "Panda link meta id={} is attempting to use a name {} which is "
              "already registered to {}",
              meta.uuid,
              meta.name,
              it->second));
        }
    } else {
        _name_index.emplace(meta.name, meta.uuid);
    }
    _underlying.insert_or_assign(meta.uuid, std::move(meta));
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
    _name_index.erase(name_it);
    _underlying.erase(it);
}

void panda_link_table::remove_link(panda_link_id id) {
    auto it = _underlying.find(id);
    if (it == _underlying.end()) {
        return;
    }
    auto name_it = _name_index.find(std::string_view(it->second.name()));
    vassert(
      name_it != _name_index.end(),
      "inconsistency: id index had a record with id: {}",
      id);
    _name_index.erase(name_it);
    _underlying.erase(it);
}

void panda_link_table::reset_links(panda_link_table::map_t snap) {
    name_index_t snap_name_index;

    ss::chunked_fifo<panda_link_id> all_deletes;
    ss::chunked_fifo<panda_link_id> all_inserted;
    ss::chunked_fifo<panda_link_id> all_changed;

    for (const auto& [k, v] : _underlying) {
        auto it = snap.find(k);
        if (it == snap.end()) {
            all_deletes.push_back(k);
        } else {
            all_changed.push_back(k);
        }
    }
    for (const auto& [k, v] : snap) {
        if (!_underlying.contains(k)) {
            all_inserted.push_back(k);
        }
        auto it = snap_name_index.insert({v.name, k});
        if (!it.second) {
            throw std::logic_error(ss::format(
              "transofmr meta id={} is attempting to use a name {} which is "
              "already registered to {}",
              k,
              v.name,
              it.first->first));
        }
    }

    _underlying = std::move(snap);
    _name_index = std::move(snap_name_index);
}

// Perform a map diff to figure out which

bool panda_link_table::name_less_cmp::operator()(
  const panda_link_name& lhs, const panda_link_name& rhs) const {
    return lhs < rhs;
}

bool panda_link_table::name_less_cmp::operator()(
  const std::string_view& lhs, const panda_link_name& rhs) const {
    return lhs < rhs();
}

bool panda_link_table::name_less_cmp::operator()(
  const panda_link_name& lhs, const std::string_view& rhs) const {
    return lhs() < rhs;
}
} // namespace cluster
