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

#include "base/seastarx.h"
#include "model/metadata.h"
#include "serde/envelope.h"
#include "utils/named_type.h"
#include "utils/unresolved_address.h"

#include <seastar/core/sstring.hh>

#include <fmt/core.h>

namespace model {

/// @brief Unique identifier for a panda link
using panda_link_id = named_type<int64_t, struct panda_link_id_tag>;

/**
 * @brief Name of the link, which is provided by the user
 */
using panda_link_name = named_type<ss::sstring, struct panda_link_name_tag>;
using panda_link_name_view
  = named_type<std::string_view, struct panda_link_name_view_tag>;
struct panda_link_metadata
  : serde::envelope<
      panda_link_metadata,
      serde::version<0>,
      serde::compat_version<0>> {
    /// Name of the link
    panda_link_name name;
    /// Bootstrap server of the source cluster
    std::vector<net::unresolved_address> source_cluster_bootstrap_server;
    /// The topics to mirror
    std::vector<model::topic_namespace> mirrored_topics;

    friend bool
    operator==(const panda_link_metadata&, const panda_link_metadata&)
      = default;

    friend std::ostream& operator<<(std::ostream&, const panda_link_metadata&);

    auto serde_fields() {
        return std::tie(name, source_cluster_bootstrap_server, mirrored_topics);
    }
};
} // namespace model

template<>
struct fmt::formatter<model::panda_link_metadata>
  : fmt::formatter<string_view> {
    auto format(const model::panda_link_metadata& m, format_context& ctx)
      -> decltype(ctx.out());
};
