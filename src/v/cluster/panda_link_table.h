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

#include "model/panda_link.h"

#include <absl/container/btree_map.h>
#include <absl/container/flat_hash_map.h>

namespace cluster {
class panda_link_table {
    using map_t
      = absl::btree_map<model::panda_link_id, model::panda_link_metadata>;

public:
    panda_link_table() = default;
    panda_link_table(const panda_link_table&) = delete;
    panda_link_table& operator=(const panda_link_table&) = delete;
    panda_link_table(panda_link_table&&) = default;
    panda_link_table& operator=(panda_link_table&&) = default;
    ~panda_link_table() = default;

    using notification_id
      = named_type<size_t, struct panda_link_notification_id_tag>;
    using notification_callback
      = ss::noncopyable_function<void(model::panda_link_id)>;

    /// Snapshot copy of all the links
    map_t all_links() const;
    /// Number of links
    size_t size() const;

    std::optional<model::panda_link_metadata>
      find_by_name(std::string_view) const;
    std::optional<model::panda_link_metadata>
    find_by_name(const model::panda_link_name&) const;
    std::optional<model::panda_link_id> find_id_by_name(std::string_view) const;
    std::optional<model::panda_link_id>
    find_id_by_name(const model::panda_link_name&) const;
    std::optional<model::panda_link_metadata>
      find_by_id(model::panda_link_id) const;

    void upsert_link(model::panda_link_id id, model::panda_link_metadata meta);
    void remove_link(const model::panda_link_name& name);
    void remove_link(model::panda_link_id id);

    void reset_links(map_t snap);

    notification_id register_for_updates(notification_callback);
    void unregister_for_updates(notification_id);

private:
    void run_callbacks(model::panda_link_id);

private:
    struct name_less_cmp {
        using is_transparent = void;
        bool operator()(
          const model::panda_link_name&, const model::panda_link_name&) const;
        bool operator()(
          const std::string_view&, const model::panda_link_name&) const;
        bool operator()(
          const model::panda_link_name&, const std::string_view&) const;
    };
    using name_index_t = absl::
      btree_map<model::panda_link_name, model::panda_link_id, name_less_cmp>;
    // The underlying data for all panda links
    map_t _underlying;
    name_index_t _name_index;
    absl::flat_hash_map<notification_id, notification_callback> _callbacks;
    notification_id _latest_id{0};
};
} // namespace cluster
