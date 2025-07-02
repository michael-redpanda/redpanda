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
class fake_partition_manager_proxy {
public:
    std::optional<ss::shard_id> shard_owner(const ::model::ktp& ktp) {
        auto it = _shard_locations.find(ktp);
        if (it == _shard_locations.end()) {
            return std::nullopt;
        }
        return it->second;
    }
    std::optional<ss::shard_id> shard_owner(const ::model::ntp& ntp) {
        auto it = _shard_locations.find(ntp);
        if (it == _shard_locations.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void set_shard_owner(const ::model::ntp& ntp, ss::shard_id shard_id) {
        _shard_locations.insert_or_assign(ntp, shard_id);
    }

    void remove_shard_owner(const ::model::ntp& ntp) {
        _shard_locations.erase(ntp);
    }

    template<typename R, typename N>
    ss::future<::result<R, cluster::errc>> invoke_on_shard_impl(
      ss::shard_id,
      const N&,
      ss::noncopyable_function<
        ss::future<::result<R, cluster::errc>>(kafka::partition_proxy*)>) {
        throw std::runtime_error("not implemented");
    }

private:
    ::model::ntp_map_type<ss::shard_id> _shard_locations;
};

class fake_partition_manager : public kafka::data::rpc::partition_manager {
public:
    explicit fake_partition_manager(fake_partition_manager_proxy* impl)
      : _impl(impl) {}

    std::optional<ss::shard_id> shard_owner(const ::model::ktp& ktp) override {
        return _impl->shard_owner(ktp);
    }

    std::optional<ss::shard_id> shard_owner(const ::model::ntp& ntp) override {
        return _impl->shard_owner(ntp);
    }

    void set_shard_owner(const ::model::ntp& ntp, ss::shard_id shard_id) {
        _impl->set_shard_owner(ntp, shard_id);
    }

    void remove_shard_owner(const ::model::ntp& ntp) {
        _impl->remove_shard_owner(ntp);
    }

    ss::future<::result<::model::offset, cluster::errc>> invoke_on_shard(
      ss::shard_id shard_id,
      const ::model::ktp& ktp,
      ss::noncopyable_function<
        ss::future<::result<::model::offset, cluster::errc>>(
          kafka::partition_proxy*)> fn) final {
        return _impl->invoke_on_shard_impl(shard_id, ktp, std::move(fn));
    }
    ss::future<::result<::model::offset, cluster::errc>> invoke_on_shard(
      ss::shard_id shard_id,
      const ::model::ntp& ntp,
      ss::noncopyable_function<
        ss::future<::result<::model::offset, cluster::errc>>(
          kafka::partition_proxy*)> fn) final {
        return _impl->invoke_on_shard_impl(shard_id, ntp, std::move(fn));
    }

private:
    fake_partition_manager_proxy* _impl;
};
class fake_partition_leader_cache_impl
  : public kafka::data::rpc::partition_leader_cache {
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
