/*
 * Copyright 2025 Redpanda Data, Inc.
 *
 * Licensed as a Redpanda Enterprise file under the Redpanda Community
 * License (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://github.com/redpanda-data/redpanda/blob/master/licenses/rcl.md
 */

#pragma once

#include "cluster/commands.h"
#include "cluster/panda_link/types.h"

#include <absl/container/flat_hash_map.h>

namespace panda_link {
/**
 * @brief Table that holds information about panda links
 */
class table : public ss::peering_sharded_service<table> {
public:
    using map_t = absl::flat_hash_map<id_t, metadata>;
    table() = default;
    table(const table&) = delete;
    table(table&&) = delete;
    table& operator=(const table&) = delete;
    table& operator=(table&&) = delete;
    ~table() = default;

    /// Number of links in the table
    size_t size() const;

    /// Finds link by name
    std::optional<std::reference_wrapper<const metadata>>
    find_link_by_name(const name_t& name) const;
    /// Finds link by id
    std::optional<std::reference_wrapper<const metadata>>
    find_link_by_id(id_t id) const;
    /// Finds link ID by name
    std::optional<id_t> find_id_by_name(const name_t& name) const;

    bool is_batch_applicable(const model::record_batch&) const;
    ss::future<std::error_code> apply_update(model::record_batch);

    ss::future<> fill_snapshot(cluster::controller_snapshot&) const;
    ss::future<>
    apply_snapshot(model::offset, const cluster::controller_snapshot&);

private:
    static constexpr auto accepted_commands = cluster::make_commands_list<
      cluster::panda_link_upsert_cmd,
      cluster::panda_link_remove_cmd>();
    using name_index_t = absl::flat_hash_map<name_t, id_t>;

    /// Snapshot copy of all the panda links
    map_t all_links() const;
    /// Restores a panda link table from a snapshot
    void reset_links(map_t);

    /// Upserts a link, if the ID classes, throws a std::logic_error
    cluster::errc upsert_link(id_t, metadata);
    /// Removes a link by ID
    cluster::errc remove_link(const name_t&);

    map_t _underlying;
    name_index_t _name_index;
};
} // namespace panda_link
