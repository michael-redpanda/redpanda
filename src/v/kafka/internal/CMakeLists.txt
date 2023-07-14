v_cc_library(
    NAME kafka_internal
    SRCS
      internal.cc
    DEPS
      Seastar::seastar
      v::rpc
      v::cluster
      v::kafka_protocol
)
