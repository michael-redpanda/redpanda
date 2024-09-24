/*
 * Copyright 2024 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#include "debug_bundle/metadata.h"

#include "bytes/streambuf.h"
#include "json/istreamwrapper.h"
#include "json/stringbuffer.h"
#include "json/writer.h"
#include "strings/string_switch.h"

#include <seastar/util/process.hh>

#include <variant>

namespace debug_bundle {
template<typename Encoding = ::json::UTF8<>>
class metadata_handler
  : public ::json::BaseReaderHandler<Encoding, metadata_handler<Encoding>> {
    enum class state {
        empty = 0,
        object,
        process_start_time_ms,
        cout,
        cerr,
        job_id,
        debug_bundle_path,
        sha256_checksum,
        process_result,
        process_result_object,
        process_result_signaled,
        process_result_signaled_object,
        terminating_signal,
        process_result_exited,
        process_result_exited_object,
        exit_code,
    };
    state _state = state::empty;

    using base_handler
      = ::json::BaseReaderHandler<Encoding, metadata_handler<Encoding>>;

public:
    using Ch = typename Encoding::Ch;
    using rjson_parse_result = metadata;
    metadata result;

    bool Key(const Ch* str, ::json::SizeType len, bool) {
        auto sv = std::string_view{str, len};
        switch (_state) {
        case state::object: {
            std::optional<state> s{
              string_switch<std::optional<state>>(sv)
                .match("process_start_time_ms", state::process_start_time_ms)
                .match("cout", state::cout)
                .match("cerr", state::cerr)
                .match("job_id", state::job_id)
                .match("debug_bundle_path", state::debug_bundle_path)
                .match("sha256_checksum", state::sha256_checksum)
                .match("process_result", state::process_result)
                .default_match(std::nullopt)};
            if (s.has_value()) {
                _state = *s;
            }
            return s.has_value();
        }
        case state::process_result_object: {
            std::optional<state> s{
              string_switch<std::optional<state>>(sv)
                .match("signaled", state::process_result_signaled)
                .match("exited", state::process_result_exited)
                .default_match(std::nullopt)};
            if (s.has_value()) {
                _state = *s;
            }
            return s.has_value();
        }
        case state::process_result_signaled_object: {
            std::optional<state> s{
              string_switch<std::optional<state>>(sv)
                .match("terminating_signal", state::terminating_signal)
                .default_match(std::nullopt)};
            if (s.has_value()) {
                _state = *s;
            }
            return s.has_value();
        }
        case state::process_result_exited_object: {
            std::optional<state> s{string_switch<std::optional<state>>(sv)
                                     .match("exit_code", state::exit_code)
                                     .default_match(std::nullopt)};
            if (s.has_value()) {
                _state = *s;
            }
            return s.has_value();
        }
        case state::empty:
        case state::process_start_time_ms:
        case state::cout:
        case state::cerr:
        case state::job_id:
        case state::debug_bundle_path:
        case state::sha256_checksum:
        case state::process_result_signaled:
        case state::process_result_exited:
        case state::process_result:
        case state::terminating_signal:
        case state::exit_code:
            return false;
        }
        return false;
    }

    bool String(const Ch* str, ::json::SizeType len, bool) {
        std::string_view str_v{str, len};
        switch (_state) {
        case state::cout:
            result.cout.emplace_back(str_v);
            return true;
        case state::cerr:
            result.cerr.emplace_back(str_v);
            return true;
        case state::job_id:
            try {
                result.job_id = job_id_t{uuid_t::from_string(str_v)};
                _state = state::object;
                return true;
            } catch (const std::exception&) {
                return false;
            }
        case state::debug_bundle_path:
            result.debug_bundle_path = std::filesystem::path(str_v);
            _state = state::object;
            return true;
        case state::sha256_checksum:
            try {
                result.sha256_checksum = base64_to_bytes(str_v);
                _state = state::object;
                return true;
            } catch (const std::exception&) {
                return false;
            }
        case state::empty:
        case state::object:
        case state::process_start_time_ms:
        case state::process_result:
        case state::process_result_object:
        case state::process_result_signaled:
        case state::process_result_signaled_object:
        case state::terminating_signal:
        case state::process_result_exited:
        case state::process_result_exited_object:
        case state::exit_code:
            return false;
        }

        return false;
    }

    bool Uint64(uint64_t i) {
        switch (_state) {
        case state::process_start_time_ms:
            result.process_start_time_ms = clock::time_point(
              std::chrono::milliseconds(i));
            _state = state::object;
            return true;
        case state::exit_code:
            result.process_result = ss::experimental::process::wait_exited{
              static_cast<int>(i)};
            _state = state::process_result_exited_object;
            return true;
        case state::terminating_signal:
            result.process_result = ss::experimental::process::wait_signaled{
              static_cast<int>(i)};
            _state = state::process_result_signaled_object;
            return true;
        case state::empty:
        case state::object:
        case state::cout:
        case state::cerr:
        case state::job_id:
        case state::debug_bundle_path:
        case state::sha256_checksum:
        case state::process_result:
        case state::process_result_object:
        case state::process_result_exited:
        case state::process_result_exited_object:
        case state::process_result_signaled:
        case state::process_result_signaled_object:
            return false;
        }
        return false;
    }

    bool Uint(unsigned i) { return Uint64(i); }

    bool StartArray() { return _state == state::cout || _state == state::cerr; }

    bool EndArray(::json::SizeType) {
        auto old_state = std::exchange(_state, state::object);
        return old_state == state::cout || old_state == state::cerr;
    }

    bool StartObject() {
        switch (_state) {
        case state::empty:
            _state = state::object;
            return true;
        case state::process_result:
            _state = state::process_result_object;
            return true;
        case state::process_result_exited:
            _state = state::process_result_exited_object;
            return true;
        case state::process_result_signaled:
            _state = state::process_result_signaled_object;
            return true;
        case state::object:
        case state::process_start_time_ms:
        case state::cout:
        case state::cerr:
        case state::job_id:
        case state::debug_bundle_path:
        case state::sha256_checksum:
        case state::process_result_object:
        case state::process_result_exited_object:
        case state::process_result_signaled_object:
        case state::terminating_signal:
        case state::exit_code:
            return false;
        }
        return false;
    }

    bool EndObject(::json::SizeType) {
        switch (_state) {
        case state::object:
            _state = state::empty;
            return true;
        case state::process_result_object:
            _state = state::object;
            return true;
        case state::process_result_exited_object:
        case state::process_result_signaled_object:
            _state = state::process_result_object;
            return true;
        case state::empty:
        case state::process_start_time_ms:
        case state::cout:
        case state::cerr:
        case state::job_id:
        case state::debug_bundle_path:
        case state::sha256_checksum:
        case state::process_result:
        case state::process_result_exited:
        case state::process_result_signaled:
        case state::terminating_signal:
        case state::exit_code:
            return false;
        }
        return false;
    }
};

ss::sstring serialize_metadata(metadata&& v) {
    ::json::StringBuffer buf;
    ::json::Writer<::json::StringBuffer> wrt{buf};
    using ::json::rjson_serialize;
    rjson_serialize(wrt, std::forward<metadata>(v));

    return ss::sstring{buf.GetString(), buf.GetSize()};
}

metadata parse_metadata_json(const char* const s) {
    ::json::Reader reader;
    ::json::StringStream ss(s);
    metadata_handler<> handler;
    if (!reader.Parse(ss, handler)) {
        throw std::runtime_error(
          fmt::format("Failed to parse at offset {}", reader.GetErrorOffset()));
    }
    return std::move(handler.result);
}

metadata parse_metadata_json(iobuf buf) {
    iobuf_istreambuf ibuf(buf);
    std::istream stream(&ibuf);
    json::IStreamWrapper wrapper(stream);
    metadata_handler<> handler;
    ::json::Reader reader;

    if (reader.Parse(wrapper, handler)) {
        return std::move(handler.result);
    } else {
        throw std::runtime_error(
          fmt::format("Failed to parse at offset {}", reader.GetErrorOffset()));
    }
}
} // namespace debug_bundle
