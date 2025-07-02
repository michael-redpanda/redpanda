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

#include "kafka/data/rpc/deps.h"

#include <seastar/util/defer.hh>
namespace cluster_link::tests {
class fake_partition_leader_cache_impl {
public:
    std::optional<::model::node_id> get_leader_node(
      ::model::topic_namespace_view tp_ns, ::model::partition_id pid) const {
        auto ntp = ::model::ntp(tp_ns.ns, tp_ns.tp, pid);
        auto it = _leader_map.find(ntp);
        if (it == _leader_map.end()) {
            return std::nullopt;
        }
        return it->second;
    }
    void set_leader_node(const ::model::ntp& ntp, ::model::node_id node_id) {
        _leader_map.insert_or_assign(ntp, node_id);
    }

private:
    chunked_hash_map<::model::ntp, ::model::node_id> _leader_map;
};

class fake_partition_leader_cache
  : public kafka::data::rpc::partition_leader_cache {
public:
    explicit fake_partition_leader_cache(fake_partition_leader_cache_impl* impl)
      : _impl(impl) {}
    std::optional<::model::node_id> get_leader_node(
      ::model::topic_namespace_view tp_ns,
      ::model::partition_id pid) const final {
        return _impl->get_leader_node(tp_ns, pid);
    }

private:
    fake_partition_leader_cache_impl* _impl;
};
} // namespace cluster_link::tests
