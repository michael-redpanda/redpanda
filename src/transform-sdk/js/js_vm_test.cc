// Copyright 2024 Redpanda Data, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "js_vm.h"

#include <gtest/gtest.h>

#include <expected>
#include <memory>

// Disabled lint checks:
// unchecked-optional: We ASSERT before, but clang-tidy doesn't understand that
// function-cognitive-complexity: Takes into account expanded macros
// NOLINTBEGIN(*-unchecked-optional-*,*-function-cognitive-complexity)

namespace {

testing::AssertionResult
compile_and_load(qjs::runtime* runtime, const std::string& code) {
    auto compile_result = runtime->compile(code);
    if (!compile_result.has_value()) {
        return testing::AssertionFailure() << std::format(
                 "unable to compile module: {}",
                 compile_result.error().val.debug_string());
    }
    auto load_result = runtime->load(compile_result.value().raw());
    if (!load_result.has_value()) {
        return testing::AssertionFailure() << std::format(
                 "unable to load module: {}",
                 load_result.error().val.debug_string());
    }
    return testing::AssertionSuccess();
}

struct native_object {
    std::expected<qjs::value, qjs::exception>
    add(JSContext* ctx, std::span<qjs::value> args) {
        if (args.size() != 2) {
            last_result.emplace(std::unexpected(
              qjs::exception::make(ctx, "wrong number of args")));
        } else if (!args.front().is_number() || !args.back().is_number()) {
            last_result.emplace(
              std::unexpected(qjs::exception::make(ctx, "wrong types")));
        } else {
            last_result.emplace(qjs::value::number(
              ctx, args.front().as_number() + args.back().as_number()));
        }
        return last_result.value();
    }

    // NOLINTNEXTLINE
    std::optional<std::expected<qjs::value, qjs::exception>> last_result;
};

} // namespace

TEST(JavascriptVMTest, LoadingCanFail) {
    qjs::runtime runtime;
    EXPECT_FALSE(compile_and_load(&runtime, R"(
      throw new Error("causes failure");
})"));
}

TEST(JavascriptVMTest, NativeModule) {
    qjs::runtime runtime;
    qjs::module_builder mod_builder("@foo/bar");
    std::optional<std::expected<qjs::value, qjs::exception>> last_result;
    mod_builder.add_function(
      "testing",
      [&last_result](
        JSContext* ctx, const qjs::value&, std::span<qjs::value> args) {
          native_object obj;
          auto result = obj.add(ctx, args);
          last_result.emplace(result);
          return result;
      });
    EXPECT_TRUE(runtime.add_module(std::move(mod_builder)));
    EXPECT_TRUE(compile_and_load(&runtime, R"(
      import {testing} from "@foo/bar";

      testing(1, 2);
)"));
    EXPECT_NE(last_result, std::nullopt);
    EXPECT_TRUE(last_result->has_value());
    EXPECT_EQ(last_result->value().as_number(), 3.0);

    EXPECT_TRUE(compile_and_load(&runtime, R"(
      import {testing} from "@foo/bar";

      try {
        testing(1);
      } catch {
        // ignore
      }
)"));
    EXPECT_FALSE(last_result->has_value());
}

TEST(JavascriptVMTest, NativeModuleAndClass) {
    qjs::runtime runtime;
    qjs::class_builder<native_object> class_builder(
      runtime.context(), "NativeObject");
    class_builder.method<&native_object::add>("add");
    auto class_factory = class_builder.build();
    auto owned_obj = std::make_unique<native_object>();
    auto* unowned_obj = owned_obj.get();
    qjs::value js_class = class_factory.create(std::move(owned_obj));
    qjs::module_builder mod_builder("@foo/bar");
    mod_builder.add_function(
      "get_obj",
      [&js_class](JSContext*, const qjs::value&, std::span<qjs::value>) {
          return js_class;
      });
    EXPECT_TRUE(runtime.add_module(std::move(mod_builder)));
    EXPECT_TRUE(compile_and_load(&runtime, R"(
      import {get_obj} from "@foo/bar";

      get_obj().add(1, 4);
)"));
    EXPECT_NE(unowned_obj->last_result, std::nullopt);
    EXPECT_TRUE(unowned_obj->last_result->has_value());
    EXPECT_EQ(unowned_obj->last_result->value().as_number(), 5.0);

    EXPECT_TRUE(compile_and_load(&runtime, R"(
      import {get_obj} from "@foo/bar";


      try {
        get_obj().add(1);
      } catch {
        // ignore
      }
)"));
    EXPECT_FALSE(unowned_obj->last_result->has_value());
}

TEST(JavascriptVMTest, Object) {
    qjs::runtime runtime;
    qjs::module_builder mod_builder("@foo/bar");
    std::optional<qjs::value> last_result;
    constexpr int num = 42;
    mod_builder.add_function(
      "object",
      [](JSContext* ctx, const qjs::value&, std::span<qjs::value>)
        -> std::expected<qjs::value, qjs::exception> {
          auto obj = qjs::value::object(ctx);
          auto result = obj.set_property("foo", qjs::value::number(ctx, num));
          if (!result.has_value()) {
              return std::unexpected(result.error());
          }
          return obj;
      });
    mod_builder.add_function(
      "testing",
      [&last_result](
        JSContext* ctx, const qjs::value&, std::span<qjs::value> args) {
          if (args.size() == 1) {
              last_result = args.front();
          }
          return qjs::value::undefined(ctx);
      });
    EXPECT_TRUE(runtime.add_module(std::move(mod_builder)));
    EXPECT_TRUE(compile_and_load(&runtime, R"(
      import {testing, object} from "@foo/bar";

      testing(object().foo);
)"));
    ASSERT_NE(last_result, std::nullopt);
    EXPECT_EQ(last_result->as_number(), num);
}

// NOLINTEND(*-unchecked-optional-*,*-function-cognitive-complexity)
