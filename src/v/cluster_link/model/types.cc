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

#include "cluster_link/model/types.h"

#include <seastar/util/variant_utils.hh>

#include <fmt/ranges.h>

namespace cluster_link::model {

mirror_topic_metadata mirror_topic_metadata::copy() const {
    mirror_topic_metadata copy;
    copy.state = state;
    copy.source_topic_id = source_topic_id;
    copy.source_topic_name = source_topic_name;
    copy.destination_topic_id = destination_topic_id;
    copy.topic_configs.reserve(topic_configs.size());
    for (const auto& [key, value] : topic_configs) {
        copy.topic_configs.emplace(key, value);
    }

    return copy;
}

auto_mirror_topic_creation_metadata
auto_mirror_topic_creation_metadata::copy() const {
    auto_mirror_topic_creation_metadata copy;

    copy.is_enabled = is_enabled;
    copy.task_interval = task_interval;
    copy.filters.reserve(filters.size());
    for (const auto& filter : filters) {
        copy.filters.emplace_back(filter);
    }

    return copy;
}

void link_state::set_mirror_topics(const mirror_topics_t& topics) {
    mirror_topics.reserve(topics.size());
    for (const auto& [topic, state] : topics) {
        mirror_topics.emplace(topic, state.copy());
    }
}

void link_state::set_mirror_topics(mirror_topics_t&& topics) {
    mirror_topics = std::move(topics);
}

link_state link_state::copy() const {
    link_state copy;
    copy.paused = paused;
    copy.mirror_topics.reserve(mirror_topics.size());
    for (const auto& [topic, state] : mirror_topics) {
        copy.mirror_topics.emplace(topic, state.copy());
    }
    copy.auto_mirror_topic_task_config = auto_mirror_topic_task_config.copy();
    return copy;
}

metadata metadata::copy() const {
    metadata copy;
    copy.name = name;
    copy.uuid = uuid;
    copy.connection = connection;
    copy.state = state.copy();
    return copy;
}

add_mirror_topic_cmd add_mirror_topic_cmd::copy() const {
    add_mirror_topic_cmd copy;
    copy.topic = topic;
    copy.metadata = metadata.copy();
    return copy;
}
} // namespace cluster_link::model

auto fmt::formatter<cluster_link::model::mirror_topic_state>::format(
  cluster_link::model::mirror_topic_state s, format_context& ctx)
  -> decltype(ctx.out()) {
    return fmt::format_to(ctx.out(), "{}", to_string_view(s));
}

auto fmt::formatter<cluster_link::model::task_state>::format(
  cluster_link::model::task_state st, format_context& ctx) const
  -> decltype(ctx.out()) {
    return fmt::format_to(ctx.out(), "{}", to_string_view(st));
}

auto fmt::formatter<cluster_link::model::scram_credentials>::format(
  const cluster_link::model::scram_credentials& c, format_context& ctx)
  -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{username={}, password=****, mechanism={}}}",
      c.username,
      c.mechanism);
}

auto fmt::formatter<
  std::optional<cluster_link::model::connection_config::authn_variant>>::
  format(
    const std::optional<cluster_link::model::connection_config::authn_variant>&
      m,
    format_context& ctx) -> decltype(ctx.out()) {
    if (!m) {
        return fmt::format_to(ctx.out(), "none");
    }
    return ss::visit(*m, [&ctx](const auto& authn) {
        return fmt::format_to(ctx.out(), "{}", authn);
    });
}

auto fmt::formatter<cluster_link::model::connection_config>::format(
  const cluster_link::model::connection_config& c, format_context& ctx)
  -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{bootstrap_servers={}, authn_config={}, cert_file_path={}, "
      "key_file_path={}, ca_file_path={}}}",
      c.bootstrap_servers,
      c.authn_config,
      c.cert_file_path,
      c.key_file_path,
      c.ca_file_path);
}

auto fmt::formatter<std::optional<model::topic_id>>::format(
  const std::optional<model::topic_id>& m, format_context& ctx)
  -> decltype(ctx.out()) {
    if (!m) {
        return fmt::format_to(ctx.out(), "none");
    }
    return fmt::format_to(ctx.out(), "{}", *m);
}

auto fmt::formatter<cluster_link::model::mirror_topic_metadata>::format(
  const cluster_link::model::mirror_topic_metadata& m,
  format_context& ctx) const -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{state={}, source_topic_id={}, source_topic_name={}, "
      "destination_topic_id={}, topic_configs={}}}",
      m.state,
      m.source_topic_id,
      m.source_topic_name,
      m.destination_topic_id,
      m.topic_configs);
}

auto fmt::formatter<
  decltype(cluster_link::model::link_state::mirror_topics)::value_type>::
  format(
    const decltype(cluster_link::model::link_state::mirror_topics)::value_type&
      m,
    format_context& ctx) const -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(), "{{topic: {}, metadata: {}}}", m.first, m.second);
}

auto fmt::formatter<cluster_link::model::filter_pattern_type>::format(
  cluster_link::model::filter_pattern_type s, format_context& ctx) const
  -> decltype(ctx.out()) {
    return fmt::format_to(ctx.out(), "{}", to_string_view(s));
}

auto fmt::formatter<cluster_link::model::filter_type>::format(
  cluster_link::model::filter_type s, format_context& ctx) const
  -> decltype(ctx.out()) {
    return fmt::format_to(ctx.out(), "{}", to_string_view(s));
}

auto fmt::formatter<cluster_link::model::topic_filter_pattern>::format(
  const cluster_link::model::topic_filter_pattern& m, format_context& ctx) const
  -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{pattern_type: {}, filter: {}, pattern: {}}}",
      m.pattern_type,
      m.filter,
      m.pattern);
}

auto fmt::formatter<cluster_link::model::auto_mirror_topic_creation_metadata>::
  format(
    const cluster_link::model::auto_mirror_topic_creation_metadata& m,
    format_context& ctx) const -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{is_enabled: {}, task_interval: {}, filters: {}}}",
      m.is_enabled,
      m.task_interval,
      m.filters);
}

auto fmt::formatter<cluster_link::model::link_state>::format(
  const cluster_link::model::link_state& s, format_context& ctx) const
  -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{paused: {}, mirror_topics: {}, auto_mirror_topic_task_config: {}}}",
      s.paused,
      fmt::join(s.mirror_topics.begin(), s.mirror_topics.end(), ","),
      s.auto_mirror_topic_task_config);
}

auto fmt::formatter<cluster_link::model::metadata>::format(
  const cluster_link::model::metadata& m, format_context& ctx)
  -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{name={}, uuid={}, connection={}, state={}}}",
      m.name,
      m.uuid,
      m.connection,
      m.state);
}

auto fmt::formatter<cluster_link::model::add_mirror_topic_cmd>::format(
  const cluster_link::model::add_mirror_topic_cmd& m, format_context& ctx)
  -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(), "{{topic={}, metadata={}}}", m.topic, m.metadata);
}

auto fmt::formatter<cluster_link::model::update_mirror_topic_state_cmd>::format(
  const cluster_link::model::update_mirror_topic_state_cmd& m,
  format_context& ctx) -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(), "{{topic={}, state={}}}", m.topic, m.state);
}

auto fmt::formatter<cluster_link::model::task_status_report>::format(
  const cluster_link::model::task_status_report& r, format_context& ctx) const
  -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{task_name={}, task_state={}, task_state_reason={}}}",
      r.task_name,
      r.task_state,
      r.task_state_reason);
}

auto fmt::formatter<decltype(cluster_link::model::link_task_status_report::
                               task_status_reports)::value_type>::
  format(
    const decltype(cluster_link::model::link_task_status_report::
                     task_status_reports)::value_type& m,
    format_context& ctx) const -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{task_name: {}, task_status_report: {}}}",
      m.first,
      m.second);
}

auto fmt::formatter<cluster_link::model::link_task_status_report>::format(
  const cluster_link::model::link_task_status_report& r,
  format_context& ctx) const -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{link_name={}, task_status_reports={}}}",
      r.link_name,
      fmt::join(
        r.task_status_reports.begin(), r.task_status_reports.end(), ","));
}

auto fmt::formatter<
  decltype(cluster_link::model::cluster_link_task_status_report::link_reports)::
    value_type>::
  format(
    const decltype(cluster_link::model::cluster_link_task_status_report::
                     link_reports)::value_type& m,
    format_context& ctx) const -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(), "{{topic: {}, metadata: {}}}", m.first, m.second);
}

auto fmt::formatter<cluster_link::model::cluster_link_task_status_report>::
  format(
    const cluster_link::model::cluster_link_task_status_report& r,
    format_context& ctx) const -> decltype(ctx.out()) {
    return fmt::format_to(
      ctx.out(),
      "{{link_reports={}}}",
      fmt::join(r.link_reports.begin(), r.link_reports.end(), ","));
}
