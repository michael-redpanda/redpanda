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

#include "cluster/panda_link_frontend.h"

#include "base/outcome.h"
#include "cluster/controller_service.h"
#include "cluster/controller_stm.h"
#include "cluster/logger.h"
#include "cluster/panda_link_table.h"
#include "cluster/partition_leaders_table.h"

namespace cluster {

using mutation_result = panda_link_frontend::mutation_result;
using model::panda_link_id;
using model::panda_link_metadata;
using model::panda_link_name;
namespace {
errc map_errc(std::error_code ec) {
    if (ec == errc::success) {
        return errc::success;
    }
    if (ec.category() == raft::error_category()) {
        switch (raft::errc(ec.value())) {
        case raft::errc::timeout:
            return errc::timeout;
        case raft::errc::not_leader:
            return errc::not_leader_controller;
        default:
            return errc::replication_error;
        }
    }
    if (ec.category() == rpc::error_category()) {
        switch (rpc::errc(ec.value())) {
        case rpc::errc::client_request_timeout:
            return errc::timeout;
        default:
            return errc::replication_error;
        }
    }
    if (ec.category() == error_category()) {
        return errc(ec.value());
    }
    return errc::replication_error;
}
} // namespace
panda_link_frontend::panda_link_frontend(
  model::node_id self,
  partition_leaders_table* leaders,
  panda_link_table* table,
  controller_stm* controller,
  rpc::connection_cache* connections,
  ss::abort_source* as)
  : _self(self)
  , _leaders(leaders)
  , _connections(connections)
  , _table(table)
  , _as(as)
  , _controller(controller) {}

ss::future<errc> panda_link_frontend::upsert_panda_link(
  panda_link_metadata meta, model::timeout_clock::time_point timeout) {
    // The ID is looked up later.
    panda_link_cmd c{panda_link_update_cmd{0, std::move(meta)}};
    auto r = co_await do_mutation(std::move(c), timeout);
    co_return r.ec;
}

ss::future<mutation_result> panda_link_frontend::delete_panda_link(
  panda_link_name name, model::timeout_clock::time_point timeout) {
    panda_link_cmd c{panda_link_remove_cmd{std::move(name), 0}};
    co_return co_await do_mutation(std::move(c), timeout);
}

std::optional<panda_link_metadata>
panda_link_frontend::lookup_panda_link(const panda_link_name& name) const {
    return _table->find_by_name(name);
}
std::optional<panda_link_metadata>
panda_link_frontend::lookup_panda_link(panda_link_id id) const {
    return _table->find_by_id(id);
}

panda_link_frontend::notification_id
panda_link_frontend::register_for_updates(notification_callback cb) {
    return _table->register_for_updates(std::move(cb));
}
void panda_link_frontend::unregister_for_updates(notification_id id) {
    _table->unregister_for_updates(id);
}

ss::future<mutation_result> panda_link_frontend::do_mutation(
  panda_link_cmd cmd, model::timeout_clock::time_point timeout) {
    auto cluster_leader = _leaders->get_leader(model::controller_ntp);
    if (!cluster_leader) {
        co_return mutation_result{.ec = errc::not_leader_controller};
    }
    if (*cluster_leader != _self) {
        co_return co_await dispatch_mutation_to_remote(
          *cluster_leader,
          std::move(cmd),
          timeout - model::timeout_clock::now());
    }
    if (ss::this_shard_id() != controller_stm_shard) {
        co_return co_await container().invoke_on(
          controller_stm_shard,
          [cmd = std::move(cmd), timeout](auto& service) mutable {
              return service.do_mutation(std::move(cmd), timeout);
          });
    }
    co_return co_await do_local_mutation(std::move(cmd), timeout);
}

ss::future<mutation_result> panda_link_frontend::dispatch_mutation_to_remote(
  model::node_id cluster_leader,
  panda_link_cmd cmd,
  model::timeout_clock::duration timeout) {
    return _connections
      ->with_node_client<controller_client_protocol>(
        _self,
        ss::this_shard_id(),
        cluster_leader,
        timeout,
        [timeout,
         cmd = std::move(cmd)](controller_client_protocol client) mutable {
            return ss::visit(
              std::move(cmd),
              [client, timeout](panda_link_update_cmd cmd) mutable {
                  return client
                    .upsert_panda_link(
                      upsert_panda_link_request{
                        .panda_link = std::move(cmd.value), .timeout = timeout},
                      rpc::client_opts(timeout))
                    .then(&rpc::get_ctx_data<upsert_panda_link_response>)
                    .then([](auto r) {
                        if (r.has_error()) {
                            return result<mutation_result>(r.error());
                        }
                        return result<mutation_result>(
                          mutation_result{.ec = r.value().ec});
                    });
              },
              [client, timeout](panda_link_remove_cmd cmd) mutable {
                  return client
                    .delete_panda_link(
                      delete_panda_link_request{
                        .name = std::move(cmd.key), .timeout = timeout},
                      rpc::client_opts(timeout))
                    .then(&rpc::get_ctx_data<delete_panda_link_response>)
                    .then([](auto r) {
                        if (r.has_error()) {
                            return result<mutation_result>(r.error());
                        }
                        return result<mutation_result>(
                          mutation_result{.ec = r.value().ec});
                    });
              });
        })
      .then([](result<mutation_result> r) {
          if (r.has_error()) {
              return mutation_result{.ec = map_errc(r.error())};
          }
          return r.value();
      });
}

ss::future<mutation_result> panda_link_frontend::do_local_mutation(
  panda_link_cmd cmd, model::timeout_clock::time_point timeout) {
    auto u = co_await _mu.get_units();
    auto result = co_await _controller->insert_linearizable_barrier(timeout);
    if (!result) {
        co_return mutation_result{.ec = errc::not_leader_controller};
    }
    auto ec = validate_mutation(cmd);
    if (ec != errc::success) {
        co_return mutation_result{.ec = ec};
    }
    bool ok = std::visit(
      [this](const auto& cmd) {
          using T = std::decay_t<decltype(cmd)>;
          return _controller->throttle<T>();
      },
      cmd);
    if (!ok) {
        co_return mutation_result{.ec = errc::throttling_quota_exceeded};
    }
    auto b = std::visit(
      [](auto cmd) { return serde_serialize_cmd(std::move(cmd)); },
      std::move(cmd));
    auto err_code = co_await _controller->replicate_and_wait(
      std::move(b), timeout, *_as);
    co_return mutation_result{.ec = map_errc(err_code)};
}

errc panda_link_frontend::validate_mutation(const panda_link_cmd& cmd) {
    validator v(_table);
    return v.validate_mutation(cmd);
}

panda_link_frontend::validator::validator(panda_link_table* table)
  : _table(table) {}

errc panda_link_frontend::validator::validate_mutation(
  const panda_link_cmd& cmd) {
    return ss::visit(
      cmd,
      [this](const panda_link_update_cmd& cmd) {
          auto existing = _table->find_by_name(cmd.value.name);
          if (existing.has_value()) {
              return errc::success;
          }
          if (cmd.value.name().empty()) {
              vlog(
                clusterlog.info,
                "attempting to create a panda link without a name");
              return errc::panda_link_invalid_create;
          }
          constexpr static size_t max_name_size = 128;
          if (cmd.value.name().size() > max_name_size) {
              vlog(
                clusterlog.info,
                "attempting to create a panda link with too large of a name {} "
                "> {}",
                cmd.value.name().size(),
                max_name_size);
              return errc::panda_link_invalid_create;
          }
          if (!is_valid_utf8(cmd.value.name())) {
              vlog(
                clusterlog.info,
                "attempting to create a panda link with an invalid name");
              return errc::panda_link_invalid_create;
          }
          if (contains_control_character(cmd.value.name())) {
              vlog(
                clusterlog.info,
                "attempting to create a panda link with an invalid name");
              return errc::panda_link_invalid_create;
          }
          if (cmd.value.source_cluster_bootstrap_server.empty()) {
              vlog(
                clusterlog.info,
                "attempting to create a panda link with an empty source "
                "cluster bootstrap address");
              return errc::panda_link_invalid_create;
          }
          if (!is_valid_utf8(cmd.value.source_cluster_bootstrap_server)) {
              vlog(
                clusterlog.info,
                "attempting to create a panda link with an invalid source "
                "cluster bootstrap address");
              return errc::panda_link_invalid_create;
          }
          if (contains_control_character(
                cmd.value.source_cluster_bootstrap_server)) {
              vlog(
                clusterlog.info,
                "attempting to create a panda link with an invalid source "
                "cluster bootstrap address");
              return errc::panda_link_invalid_create;
          }
          return errc::success;
      },
      [this](const panda_link_remove_cmd& cmd) {
          auto meta = _table->find_by_name(cmd.key);
          if (!meta) {
              return errc::panda_link_does_not_exist;
          }
          return errc::success;
      });
}

} // namespace cluster
