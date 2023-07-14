/*
 * Copyright 2023 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#include "internal.h"

namespace kafka::internal {
    internal::internal(
  ss::sharded<cluster::metadata_cache>& metadata_cache,
  ss::sharded<cluster::topics_frontend>& topics_frontend,
  ss::sharded<cluster::partition_manager>& partition_manager) noexcept
  : _metadata_cache(metadata_cache)
  , _topics_frontend(topics_frontend)
  , _partition_manager(partition_manager) {

  }
} // namespace kafka::internal
