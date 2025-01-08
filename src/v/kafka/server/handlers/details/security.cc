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

#include "kafka/server/handlers/details/security.h"

namespace kafka::details {
scram_mechanism
security_to_kafka_mechanism(security::scram_algorithm_t mechanism) {
    switch (mechanism) {
    case security::scram_algorithm_t::sha256:
        return kafka::scram_mechanism::scram_sha_256;
    case security::scram_algorithm_t::sha512:
        return kafka::scram_mechanism::scram_sha_512;
    }
    __builtin_unreachable();
}

std::optional<security::scram_algorithm_t>
kafka_to_security_mechanism(kafka::scram_mechanism mechanism) {
    switch (mechanism) {
    case kafka::scram_mechanism::unknown:
        return std::nullopt;
    case kafka::scram_mechanism::scram_sha_256:
        return security::scram_algorithm_t::sha256;
    case kafka::scram_mechanism::scram_sha_512:
        return security::scram_algorithm_t::sha512;
    }
    return std::nullopt;
}
} // namespace kafka::details
