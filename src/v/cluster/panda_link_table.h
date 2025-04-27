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

#include "model/metadata.h"
#include "model/panda_link.h"

#include <absl/container/btree_map.h>

namespace cluster {

/**
 * @brief This table is used to store the settings for panda links
 */
class panda_link_table {
    using map_t
      = absl::btree_map<model::panda_link_id, model::panda_link_metadata>;

public:
    panda_link_table() = default;
    panda_link_table(const panda_link_table&) = delete;
    panda_link_table(panda_link_table&&) = delete;
    panda_link_table& operator=(const panda_link_table&) = delete;
    panda_link_table& operator=(panda_link_table&&) = delete;
    ~panda_link_table() = default;

    /// Used to get a snapshot copy of all the panda links
    map_t all_links() const;
    /// Nubmer of links in the table
    size_t size() const;
    /// Restores the panda link table from a snapshot
    void reset_links(map_t);

private:
    struct name_less_cmp {
        using is_transparent = void;
        bool operator()(
          const model::panda_link_name& lhs,
          const model::panda_link_name& rhs) const;
        bool operator()(
          const model::panda_link_name&, const std::string_view&) const;
        bool operator()(
          const std::string_view&, const model::panda_link_name&) const;
    };

    using name_index_t = absl::
      btree_map<model::panda_link_name, model::panda_link_id, name_less_cmp>;

    /// This variant is used in the map of topics to panda links
    /// The "all_topics_tag" indicates a panda link that is set to auto create
    /// mirrored topics.  The purpose is to prevent multiple links from
    /// targeting the same mirror topics, so if "all_topics_tag" is the entry,
    /// that indicates that that link owns all mirror topics.
    struct all_topics_tag {};
    using topic_map_entry
      = std::variant<all_topics_tag, model::topic_namespace>;

    struct topic_map_less_cmp {
        using is_transparent = void;
        bool operator()(const topic_map_entry&, const topic_map_entry&) const;
    };

    using topic_index_t = absl::
      btree_map<topic_map_entry, model::panda_link_id, topic_map_less_cmp>;

    map_t _underlying;
    name_index_t _name_index;
    topic_index_t _topic_index;
};
} // namespace cluster
