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

#include "base/outcome.h"
#include "cluster_link/api.h"
#include "redpanda/admin/api-doc/panda_link.json.hh"
#include "redpanda/admin/server.h"

#include <seastar/util/short_streams.hh>

#include <rapidjson/error/en.h>

namespace {
struct error_info {
    ss::sstring message;
    int errc;
};

template<typename T>
using result = result<T, error_info>;

ss::future<result<json::Document>> as_json_doc(ss::http::request* req) {
    json::Document doc;
    auto content = co_await ss::util::read_entire_stream_contiguous(
      *req->content_stream);
    doc.Parse(content);
    if (doc.HasParseError()) {
        co_return error_info{
          .message = ssx::sformat(
            "JSON parse error: {} at offset {}",
            rapidjson::GetParseError_En(doc.GetParseError()),
            doc.GetErrorOffset()),
          .errc = 1};
    } else {
        co_return std::move(doc);
    }
}

template<typename T>
std::unique_ptr<ss::http::reply> make_json_body(
  ss::http::reply::status_type status,
  T&& t,
  std::unique_ptr<ss::http::reply> rep) {
    rep->set_status(status);
    rep->write_body("json", ss::json::stream_object(std::forward<T>(t)));
    return rep;
}

std::unique_ptr<ss::http::reply> make_error_body(
  int errc, const ss::sstring& msg, std::unique_ptr<ss::http::reply> rep) {
    ss::httpd::panda_link_json::error_body body;
    body.code = errc;
    body.message = msg;

    auto status = ss::http::reply::status_type::internal_server_error;

    return make_json_body(status, body, std::move(rep));
}

std::unique_ptr<ss::http::reply>
make_error_body(const error_info& err, std::unique_ptr<ss::http::reply> rep) {
    return make_error_body(err.errc, err.message, std::move(rep));
}

inline std::string_view as_string_view(const json::Value& v) {
    vassert(v.IsString(), "You must check that v is a string;");
    return {v.GetString(), v.GetStringLength()};
}

template<typename T>
result<T> from_json(
  const json::Document::ConstObject& p, std::string_view f, bool required);

template<typename T>
result<T> from_json(const json::Value& v) {
    constexpr auto parse_error = [](std::string_view extra_message) {
        return error_info{
          .message = ssx::sformat("Failed to parse{}", extra_message),
          .errc = 1};
    };

    if constexpr (reflection::is_rp_named_type<T>) {
        auto r = from_json<typename T::type>(v);
        if (r.has_value()) {
            return T{std::move(r).assume_value()};
        }
    } else if constexpr (std::is_same_v<T, ss::sstring>) {
        if (v.IsString()) {
            auto vv = as_string_view(v);
            try {
                validate_no_control(vv);
            } catch (const std::runtime_error& e) {
                return parse_error(
                  ssx::sformat(": invalid control character: {}", e.what()));
            }
            return T{vv};
        }
    } else {
        static_assert(always_false_v<T>, "Not implemented");
    }

    return parse_error(": unsupported type");
}

template<typename T>
result<T> from_json(
  const json::Document::ConstObject& p, std::string_view f, bool required) {
    auto it = p.FindMember(json::Document::StringRefType{
      f.data(), static_cast<rapidjson::SizeType>(f.length())});
    if (required && it == p.MemberEnd()) {
        return error_info{
          .message = ssx::sformat("Failed to parse: field '{}' is required", f),
          .errc = 1};
    };
    if (it == p.MemberEnd()) {
        return outcome::success();
    }
    if (auto r = from_json<T>(it->value); r.has_error()) {
        return error_info{
          .message = ssx::sformat(
            "{} for field '{}'", r.assume_error().message, f),
          .errc = 1};
    } else {
        return r;
    }
}

std::vector<net::unresolved_address>
parse_addresses(std::string_view addresses) {
    constexpr std::string_view delimiter = ",";
    std::vector<net::unresolved_address> result;

    auto split_view = addresses | std::views::split(delimiter);
    for (auto&& part : split_view) {
        std::string_view addr = std::string_view(
          &*part.begin(), std::ranges::distance(part));
        auto colon_pos = addr.find(':');
        if (colon_pos == std::string_view::npos) {
            throw std::invalid_argument(
              fmt::format("Invalid address format: {}", addr));
        }
        auto host = addr.substr(0, colon_pos);
        auto port_str = addr.substr(colon_pos + 1);
        int port = std::stoi(std::string(port_str));
        result.emplace_back(std::string(host), port);
    }

    return result;
}
} // namespace

void admin_server::register_panda_link_routes() {
    register_route_raw_async<superuser>(
      ss::httpd::panda_link_json::post_panda_link,
      [this](
        std::unique_ptr<ss::http::request> req,
        std::unique_ptr<ss::http::reply> rep) {
          return post_panda_link(std::move(req), std::move(rep));
      });
}

ss::future<std::unique_ptr<ss::http::reply>> admin_server::post_panda_link(
  std::unique_ptr<ss::http::request> req,
  std::unique_ptr<ss::http::reply> rep) {
    const auto json_doc = co_await as_json_doc(req.get());
    if (json_doc.has_error()) {
        co_return make_error_body(
          std::move(json_doc).assume_error(), std::move(rep));
    }
    if (!json_doc.assume_value().IsObject()) {
        co_return make_error_body(
          1, "Request body is not a JSON object", std::move(rep));
    }
    const auto& obj = json_doc.assume_value().GetObject();

    auto name = from_json<model::panda_link_name>(obj, "name", true);
    if (name.has_error()) {
        co_return make_error_body(
          std::move(name).assume_error(), std::move(rep));
    }

    auto bootstrap_servers = from_json<ss::sstring>(
      obj, "source_bootstrap_server", true);
    if (bootstrap_servers.has_error()) {
        co_return make_error_body(
          std::move(bootstrap_servers).assume_error(), std::move(rep));
    }

    auto name_copy = name.assume_value();
    auto bootstrap_servers_copy = bootstrap_servers.assume_value();

    model::panda_link_metadata metadata{
      .name = std::move(name).assume_value(),
      .source_cluster_bootstrap_server = parse_addresses(
        bootstrap_servers.assume_value()),
    };

    auto res = co_await _cluster_link_service.local().create_link(
      std::move(metadata));
    if (res) {
        co_return make_error_body(res.value(), res.message(), std::move(rep));
    }

    ss::httpd::panda_link_json::panda_link_create_response body;
    body.link_name = name_copy;
    body.source_bootstrap_server = bootstrap_servers_copy;
    body.id = uuid_t::create();
    co_return make_json_body(
      ss::http::reply::status_type::created, body, std::move(rep));
}
