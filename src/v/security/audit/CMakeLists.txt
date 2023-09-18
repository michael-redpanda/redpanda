v_cc_library(
    NAME audit
    SRCS
      schemas/application_activity.cc
    DEPS
      v::json
      v::rphashing
      v::security
      absl::flat_hash_map
)

add_subdirectory(schemas)
