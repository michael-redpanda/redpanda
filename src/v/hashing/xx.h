/*
 * Copyright 2020 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#pragma once

#include "seastarx.h"

#include <seastar/core/sstring.hh>

#include <cstdint>
#include <cstring>
#include <functional>
#include <string_view>
#include <xxhash.h>

inline uint64_t xxhash_64(const unsigned char* data, size_t length) {
    return XXH64(data, length, 0);
}
inline uint32_t xxhash_32(const unsigned char* data, size_t length) {
    return XXH32(data, length, 0);
}

inline uint64_t xxhash_64(const char* data, const size_t& length) {
    return XXH64(data, length, 0);
}
inline uint32_t xxhash_32(const char* data, const size_t& length) {
    return XXH32(data, length, 0);
}

class incremental_xxhash64;

template<auto& CPO>
using tag_t = std::remove_cvref_t<decltype(CPO)>;

inline constexpr struct incremental_xxhash64_tag_fn {
    template<typename T>
    void operator()(incremental_xxhash64& hash, const T& x) const {
        return tag_invoke(*this, hash, x);
    }
} incremental_xxhash64_tag{};

template<typename T>
void tag_invoke(
  tag_t<incremental_xxhash64_tag>, incremental_xxhash64&, const T&);

template<
  typename T,
  typename std::enable_if_t<
    std::is_convertible_v<T, typename T::type>>* = nullptr>
void tag_invoke(
  tag_t<incremental_xxhash64_tag>, incremental_xxhash64& h, const T& t);

template<
  typename T,
  typename std::enable_if_t<
    std::is_enum_v<T> || std::is_integral_v<T>>* = nullptr>
void tag_invoke(tag_t<incremental_xxhash64_tag>, incremental_xxhash64& h, T);

template<typename T>
concept hash_tag_invocable = std::invocable<
  decltype(tag_invoke<T>),
  tag_t<incremental_xxhash64_tag>,
  incremental_xxhash64&,
  const T&>;

class incremental_xxhash64 {
public:
    explicit incremental_xxhash64(uint64_t seed = 0) {
        XXH64_reset(&_state, seed);
    }
    incremental_xxhash64(incremental_xxhash64&&) noexcept = default;
    incremental_xxhash64& operator=(incremental_xxhash64&&) noexcept = default;

    void update(const char* src, const std::size_t sz) {
        XXH64_update(&_state, src, sz);
    }

    // string override
    void update(std::string_view str) { update(str.data(), str.size()); }

    void update(const ss::sstring& str) { update(str.data(), str.size()); }

    // named type override
    template<
      typename T,
      typename std::enable_if_t<
        std::is_convertible_v<T, typename T::type>>* = nullptr>
    void update(const T& named_type) {
        update(named_type());
    }

    template<
      typename T,
      typename std::enable_if_t<
        std::is_enum_v<T> || std::is_integral_v<T>>* = nullptr>
    void update(T t) {
        update((const char*)&t, sizeof(T));
    }
    template<typename... T>
    void update_all(T... t) {
        (update(t), ...);
    }

    template<typename T>
    requires hash_tag_invocable<T>
    void update(const T& t) {
        incremental_xxhash64_tag(*this, t);
    }

    uint64_t digest() { return XXH64_digest(&_state); }

private:
    XXH64_state_t _state{};
};

template<
  typename T,
  typename std::enable_if_t<std::is_enum_v<T> || std::is_integral_v<T>>*>
void tag_invoke(tag_t<incremental_xxhash64_tag>, incremental_xxhash64& h, T t) {
    h.update((const char*)&t, sizeof(T));
}

template<
  typename T,
  std::size_t N,
  typename = std::enable_if_t<std::is_integral<T>::value>>
inline uint64_t xxhash_64(const std::array<T, N>& arr) {
    return xxhash_64(reinterpret_cast<const char*>(&arr[0]), sizeof(T) * N);
}
template<
  typename T,
  std::size_t N,
  typename = std::enable_if_t<std::is_integral<T>::value>>
inline uint32_t xxhash_32(const std::array<T, N>& arr) {
    return xxhash_32(reinterpret_cast<const char*>(&arr[0]), sizeof(T) * N);
}
inline uint64_t xxhash_64_str(const char* s) {
    return xxhash_64(s, std::strlen(s));
}
inline uint32_t xxhash_32_str(const char* s) {
    return xxhash_32(s, std::strlen(s));
}
