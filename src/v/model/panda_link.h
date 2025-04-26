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

#include "base/seastarx.h"
#include "container/fragmented_vector.h"
#include "serde/envelope.h"
#include "utils/named_type.h"
#include "utils/unresolved_address.h"

#include <seastar/core/sstring.hh>
#include <seastar/util/bool_class.hh>

#include <fmt/core.h>

namespace model {
/// ID of the panda link
using panda_link_id = named_type<int64_t, struct panda_link_id_tag>;

/// Name of the panda link
using panda_link_name = named_type<ss::sstring, struct panda_link_name_tag>;

using panda_link_auto_create_topics_t
  = ss::bool_class<struct panda_link_auto_create_topics_tag>;

/// Configuration for the panda link - collection of settings that are
/// modifiable once the panda link has been created
struct panda_link_config
  : serde::
      envelope<panda_link_config, serde::version<0>, serde::compat_version<0>> {
    /// Whether or not to automatically created topics
    panda_link_auto_create_topics_t panda_link_auto_create_topics{true};
    /// List of topics to mirror - ignored if panda_link_auto_create_topics is
    /// true
    std::vector<ss::sstring> mirrored_topics;

    friend bool operator==(const panda_link_config&, const panda_link_config&)
      = default;
    friend std::ostream& operator<<(std::ostream&, const panda_link_config&);

    auto serde_fields() {
        return std::tie(panda_link_auto_create_topics, mirrored_topics);
    }
};

struct panda_link_connection
  : serde::envelope<
      panda_link_connection,
      serde::version<0>,
      serde::compat_version<0>> {
    /// The address of the source cluster
    std::vector<net::unresolved_address> source_bootstrap_server;

    friend bool
    operator==(const panda_link_connection&, const panda_link_connection&)
      = default;
    friend std::ostream&
    operator<<(std::ostream&, const panda_link_connection&);
    auto serde_fields() { return std::tie(source_bootstrap_server); }
};

struct panda_link_metadata
  : serde::envelope<
      panda_link_metadata,
      serde::version<0>,
      serde::compat_version<0>> {
    /// The name of the panda link
    panda_link_name name;
    /// The connection information for the panda link
    panda_link_connection connection;
    /// The configuration for the panda link
    panda_link_config config;

    friend bool
    operator==(const panda_link_metadata&, const panda_link_metadata&)
      = default;
    friend std::ostream& operator<<(std::ostream&, const panda_link_metadata&);
    auto serde_fields() { return std::tie(name, connection, config); }
};

} // namespace model

template<>
struct fmt::formatter<model::panda_link_config> : fmt::formatter<string_view> {
    auto format(const model::panda_link_config&, format_context& ctx)
      -> decltype(ctx.out());
};

template<>
struct fmt::formatter<model::panda_link_connection>
  : fmt::formatter<string_view> {
    auto format(const model::panda_link_connection&, format_context& ctx)
      -> decltype(ctx.out());
};
template<>
struct fmt::formatter<model::panda_link_metadata>
  : fmt::formatter<string_view> {
    auto format(const model::panda_link_metadata&, format_context& ctx)
      -> decltype(ctx.out());
};
