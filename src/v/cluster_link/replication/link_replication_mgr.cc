/*
 * Copyright 2025 Redpanda Data, Inc.
 *
 * Licensed as a Redpanda Enterprise file under the Redpanda Community
 * License (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://github.com/redpanda-data/redpanda/blob/master/licenses/rcl.md
 */

#include "cluster_link/replication/link_replication_mgr.h"

#include "base/units.h"
#include "cluster_link/logger.h"
#include "ssx/future-util.h"
#include "utils/to_string.h"

using namespace std::chrono_literals;

namespace cluster_link::replication {

link_replication_manager::link_replication_manager(
  ss::scheduling_group sg,
  std::unique_ptr<data_source_factory> source_factory,
  std::unique_ptr<data_sink_factory> sink_factory)
  : _sg(sg)
  , _source_factory(std::move(source_factory))
  , _sink_factory(std::move(sink_factory))
  , _queue(_sg, [](const std::exception_ptr& ex) {
      vlog(cllog.error, "unexpected error in processing notifications: {}", ex);
  }) {}

ss::future<> link_replication_manager::start() {
    co_await _source_factory->start();
    ssx::repeat_until_gate_closed(_gate, [this] {
        return reconcile().handle_exception([](const std::exception_ptr& e) {
            auto level = ssx::is_shutdown_exception(e) ? ss::log_level::debug
                                                       : ss::log_level::error;
            vlogl(cllog, level, "reconciliation loop failed: {}", e);
        });
    });
}

ss::future<> link_replication_manager::stop() {
    vlog(cllog.trace, "Stopping link replication manager");
    // to avoid further submissions to the queue.
    _pending_changes_cv.broken();
    auto f = _gate.close();
    co_await _queue.shutdown();
    co_await std::move(f);
    // stop any pending replicators
    for (auto& [_, replicator] : _replicators) {
        co_await replicator->stop();
    }
    _replicators.clear();
    co_await _source_factory->stop();
    vlog(cllog.trace, "Link replication manager stopped");
}

ss::future<> link_replication_manager::do_start_replicator(
  model::ntp ntp, model::term_id term) {
    auto holder = _gate.hold();
    vlog(cllog.debug, "Starting replicator for {}", ntp);
    auto it = _replicators.find(ntp);
    vassert(
      it == _replicators.end(),
      "Replicator for {} already exists, an instance should be stopped before "
      "starting a new one",
      ntp);
    auto source = _source_factory->make_source(ntp);
    auto sink = _sink_factory->make_sink(ntp);
    auto replicator = std::make_unique<partition_replicator>(
      ntp, term, std::move(source), std::move(sink), _sg);
    auto [r_it, _] = _replicators.emplace(ntp, std::move(replicator));
    co_await r_it->second->start();
}

void link_replication_manager::start_replicator(
  model::ntp ntp, model::term_id term) {
    if (_gate.is_closed()) {
        return;
    }

    // If we are starting replication, check to see if there is a pending stop.
    // If one exists and its term is higher than ours, then do not enqueue the
    // start action, otherwise remove the stop action
    auto stop_it = _pending_stops.find(ntp);
    if (stop_it != _pending_stops.end()) {
        if (stop_it->second.has_value() && term <= *stop_it->second) {
            vlog(
              cllog.debug,
              "Not enqueueing start action for {} at term {}, a stop is "
              "pending with term {}",
              ntp,
              term,
              stop_it->second);
            return;
        }
        vlog(cllog.debug, "Removing pending stop action for {}", ntp);
        _pending_stops.erase(stop_it);
    }

    // Now check if there are any pending starts.  If there are, replace the
    // start only if the term is higher
    auto start_it = _pending_starts.find(ntp);
    if (start_it != _pending_starts.end()) {
        if (term <= start_it->second) {
            vlog(
              cllog.debug,
              "Not enqueueing start action for {} at term {}, a start is "
              "pending with term {}",
              ntp,
              term,
              start_it->second);
            return;
        }
    }
    vlog(cllog.debug, "Enqueueing start action for {} at term {}", ntp, term);
    _pending_starts.insert_or_assign(ntp, term);
    _pending_changes_cv.signal();
}

ss::future<> link_replication_manager::do_stop_replicator(
  model::ntp ntp, std::optional<model::term_id> term) {
    auto holder = _gate.hold();
    vlog(cllog.debug, "Stopping replicator for {}", ntp);
    auto it = _replicators.find(ntp);
    if (it == _replicators.end() || (term && (*term < it->second->term()))) {
        vlog(
          cllog.trace,
          "No replicator found for {} at term {}, skipping stop",
          ntp,
          term);
        co_return;
    }
    auto replicator = std::move(it->second);
    _replicators.erase(it);
    co_await replicator->stop();
}

void link_replication_manager::stop_replicator(
  model::ntp ntp, std::optional<model::term_id> term) {
    if (_gate.is_closed()) {
        return;
    }

    // If we are stopping replication, we need to check if there are any pending
    // starting or stopping operations.  If there are pending starts and the
    // term is higher or not present, enqueue the stop and remove the start
    auto start_it = _pending_starts.find(ntp);
    if (start_it != _pending_starts.end()) {
        if (term.has_value() && *term < start_it->second) {
            vlog(
              cllog.debug,
              "Not enqueueing stop action for {} at term {}",
              ntp,
              term);
            return;
        }
        vlog(cllog.debug, "Removing pending start action for {}", ntp);
        _pending_starts.erase(start_it);
    }

    auto stop_it = _pending_stops.find(ntp);
    if (stop_it != _pending_stops.end()) {
        if (
          term.has_value() && stop_it->second.has_value()
          && *term <= *stop_it->second) {
            vlog(
              cllog.debug,
              "Not enqueueing stop action for {} at term {}, a stop is "
              "pending with term {}",
              ntp,
              term,
              stop_it->second);
            return;
        }
    }
    vlog(cllog.debug, "Enqueuing stop action for {} at term {}", ntp, term);
    _pending_stops.insert_or_assign(ntp, term);
    _pending_changes_cv.signal();
}

void link_replication_manager::stop_replicators(
  std::optional<::model::topic> topic) {
    if (_gate.is_closed()) {
        return;
    }
    for (const auto& [ntp, _] : _replicators) {
        if (!topic || ntp.tp.topic == *topic) {
            stop_replicator(ntp, std::nullopt);
        }
    }
}

bool link_replication_manager::has_pending_actions() {
    return !_pending_starts.empty() || !_pending_stops.empty();
}

ss::future<> link_replication_manager::reconcile() {
    co_await _pending_changes_cv.wait([this] { return has_pending_actions(); });
    if (_gate.is_closed()) {
        co_return;
    }
    run_stop_actions();
    run_start_actions();
}

void link_replication_manager::run_start_actions() {
    for (auto& [ntp, term] : _pending_starts) {
        vlog(cllog.trace, "Starting {} term {}", ntp, term);
        _queue.submit([this, ntp = std::move(ntp), term]() mutable {
            return do_start_replicator(ntp, term).handle_exception(
              [ntp = std::move(ntp),
               term](const std::exception_ptr& e) mutable {
                  vlog(
                    cllog.error,
                    "Failed to start replicator for {} at term {}: {}",
                    ntp,
                    term,
                    e);
              });
        });
    }
    _pending_starts.clear();
}

void link_replication_manager::run_stop_actions() {
    for (auto& [ntp, term] : _pending_stops) {
        vlog(cllog.trace, "Stopping {} term {}", ntp, term);
        _queue.submit([this, ntp = std::move(ntp), term]() mutable {
            return do_stop_replicator(ntp, term).handle_exception(
              [ntp = std::move(ntp),
               term](const std::exception_ptr& e) mutable {
                  vlog(
                    cllog.error,
                    "Failed to stop replicator for {} at term {}: {}",
                    ntp,
                    term,
                    e);
              });
        });
    }
    _pending_stops.clear();
}

} // namespace cluster_link::replication
