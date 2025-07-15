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

cluster_link::cluster_link(const client_configuration& config)
  : _logger(kclog, config.connection_cfg.client_id.value_or("kafka-monitoring"))
  , _cluster(config.connection_cfg) {}

ss::future<> cluster_link::connect() {
    vlog(_logger.trace, "Connect called");
    if (!_is_started) {
        co_await _cluster.start();
        _is_started = true;
        vlog(_logger.trace, "Successfully connected to cluster");
    }
}

ss::future<> cluster_link::stop() noexcept {
    vlog(_logger.trace, "Stop called");
    _as.request_abort();
    co_await catch_and_log(_logger, [this] { return _cluster.stop(); });
    vlog(_logger.trace, "Successfully stopped client");
}

prefix_logger& cluster_link::logger() { return _logger; }
} // namespace kafka::client
