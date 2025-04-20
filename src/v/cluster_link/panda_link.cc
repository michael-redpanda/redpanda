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

#include "cluster_link/panda_link.h"

#include "base/vlog.h"
#include "cluster_link/logger.h"

#include <seastar/util/later.hh>

namespace cluster_link {
panda_link::panda_link(ss::sstring source_broker_bootstrap_server)
  : _source_broker_bootstrap_server(std::move(source_broker_bootstrap_server)) {
}

ss::future<> panda_link::start() {
    vlog(
      cllog.trace,
      "Starting panda link to {}",
      _source_broker_bootstrap_server);
    return ss::now();
}

ss::future<> panda_link::stop() {
    vlog(
      cllog.trace,
      "Stopping panda link to {}",
      _source_broker_bootstrap_server);
    return ss::now();
}

} // namespace cluster_link
