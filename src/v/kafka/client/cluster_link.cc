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

#include "kafka/client/cluster_link.h"

#include "cluster_link/model/filter_utils.h"
#include "cluster_link/model/types.h"
#include "kafka/data/rpc/deps.h"
#include "utils/prefix_logger.h"

namespace kafka::client {

namespace {
template<typename Func>
ss::future<> catch_and_log(const prefix_logger& logger, Func&& f) noexcept {
    return ss::futurize_invoke(std::forward<Func>(f))
      .discard_result()
      .handle_exception([&logger](std::exception_ptr e) {
          vlog(logger.debug, "exception during stop: {}", e);
      });
}
} // namespace

using ::cluster_link::model::add_mirror_topic_cmd;
using ::cluster_link::model::id_t;
using data::rpc::topic_metadata_cache;

static constexpr int32_t required_permissions
  = 0x508; // DESCRIBE_CONFIG, DESCRIBE, READ

cluster_link::cluster_link(
  const client_configuration& config,
  std::unique_ptr<link_registry> link_registry,
  std::unique_ptr<topic_metadata_cache> topic_metadata_cache)
  : _link_registry(std::move(link_registry))
  , _topic_metadata_cache(std::move(topic_metadata_cache))
  , _logger(kclog, config.connection_cfg.client_id.value_or("kafka-monitoring"))
  , _cluster(config.connection_cfg) {}

ss::future<> cluster_link::connect() {
    vlog(_logger.trace, "Connect called");
    if (!_is_started) {
        co_await _cluster.start();
        _is_started = true;
        _supported_api_versions_describe_configs
          = co_await _cluster.supported_api_versions(describe_configs_api::key);
        if (!_supported_api_versions_describe_configs) {
            throw std::runtime_error(
              "DescribeConfigs API is not supported by the cluster");
        }
        vlog(_logger.trace, "Successfully connected to cluster");
    }
}

ss::future<> cluster_link::update_mirror_topic_state(id_t link_id) {
    vlog(_logger.trace, "Running update mirror topic state action");
    vassert(
      _is_started,
      "Cluster link must be started before updating mirror topics");
    vassert(
      _supported_api_versions_describe_configs.has_value(),
      "DescribeConfigs API is not supported by the cluster");

    auto link_metadata = _link_registry->find_link_by_id(link_id);
    if (!link_metadata) {
        vlog(_logger.warn, "Link with id={} not found", link_id);
        co_return;
    }

    const auto& auto_topic_create_settings
      = link_metadata->state.auto_mirror_topic_task_config;

    co_await _cluster.request_metadata_update();
    auto& client_topic_cache = _cluster.get_topics();

    for (const auto& [topic, md] : client_topic_cache.topics()) {
        vlog(_logger.trace, "Checking topic {}", topic);
        auto topic_config = _topic_metadata_cache->find_topic_cfg(
          {model::kafka_namespace, topic});
        if (topic_config.has_value()) {
            vlog(_logger.trace, "Topic {} already exists, skipping", topic);
            continue;
        }

        if (::cluster_link::model::select_topic(
              topic, auto_topic_create_settings.filters)) {
            vlog(_logger.trace, "Topic {} matched filter", topic);
        } else {
            vlog(_logger.trace, "Topic {} did not match filter", topic);
            continue;
        }
        vlog(
          _logger.trace,
          "Checking permissions for topic {} ({:08x})",
          topic,
          md.authorized_operations);
        if (
          (md.authorized_operations & required_permissions)
          != required_permissions) {
            vlog(
              _logger.trace,
              "Not enough permissions to mirror topic {} ({:08x}). "
              "Requires "
              "{:08x}",
              topic,
              md.authorized_operations,
              required_permissions);
            continue;
        }

        vlog(_logger.info, "Topic {} is eligible for mirroring", topic);

        describe_configs_response resp;
        try {
            resp = co_await describe_topic(topic);
        } catch (const std::exception& e) {
            vlog(
              _logger.warn, "Failed to describe topic {}: {}", topic, e.what());
            continue;
        }
        if (resp.data.results.empty()) {
            vlog(
              _logger.warn,
              "Failed to describe topic {}: no resources found",
              topic);
            continue;
        }
        if (resp.data.results[0].error_code != error_code::none) {
            vlog(
              _logger.warn,
              "Failed to describe topic {}: {} ({})",
              topic,
              resp.data.results[0].error_code,
              resp.data.results[0].error_message);
            continue;
        }
        if (resp.data.results[0].resource_name != topic) {
            vlog(
              _logger.warn,
              "DescribeConfigs returned unexpected topic name: {} (expected "
              "{})",
              resp.data.results[0].resource_name,
              topic);
            continue;
        }

        auto& topic_configs = resp.data.results[0].configs;
        chunked_hash_map<ss::sstring, ss::sstring> configs;
        configs.reserve(topic_configs.size());
        for (const auto& config : topic_configs) {
            if (config.value.has_value()) {
                configs.emplace(config.name, config.value.value());
            }
        }
        vlog(_logger.trace, "Adding topic {} with configs: {}", topic, configs);

        add_mirror_topic_cmd cmd{
          .topic = topic,
          .metadata = {
            .source_topic_name = topic,
            .destination_topic_id = ::model::topic_id(uuid_t::create()),
            .topic_configs = std::move(configs)}};

        auto ec = co_await _link_registry->add_mirror_topic(
          link_id, std::move(cmd), model::timeout_clock::now());
        if (ec != ::cluster::cluster_link::errc::success) {
            vlog(_logger.warn, "Failed to add mirror topic {}: {}", topic, ec);
            continue;
        } else {
            vlog(_logger.info, "Successfully added mirror topic {}", topic);
        }
    }
}

ss::future<> cluster_link::stop() noexcept {
    vlog(_logger.trace, "Stop called");
    _as.request_abort();
    co_await catch_and_log(_logger, [this] { return _cluster.stop(); });
    vlog(_logger.trace, "Successfully stopped client");
}

prefix_logger& cluster_link::logger() { return _logger; }

ss::future<describe_configs_response> cluster_link::describe_topic(
  model::topic topic,
  std::optional<chunked_vector<ss::sstring>> configuration_keys) {
    vlog(_logger.trace, "Describing topic {}", topic);
    describe_configs_request request;
    request.data.resources.emplace_back(describe_configs_resource{
      .resource_type = config_resource_type::topic,
      .resource_name = std::move(topic),
      .configuration_keys = std::move(configuration_keys)});

    request.data.include_synonyms = false;
    request.data.include_documentation = false;

    co_return co_await _cluster.dispatch_to_any(
      std::move(request),
      std::min(
        _supported_api_versions_describe_configs->max,
        describe_configs_api::max_valid));
}
} // namespace kafka::client
