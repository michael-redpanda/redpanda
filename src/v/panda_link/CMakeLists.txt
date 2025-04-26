v_cc_library(
    NAME panda_link_logger
    SRCS
        logger.cc
    DEPS
        v::ssx
)

v_cc_library(
    NAME write_at_offset_stm
    SRCS
        write_at_offset_stm.cc
    DEPS
        v::panda_link_logger
        v::cluster
        v::model
        v::raft
        v::raft_fixture
)

add_subdirectory(tests)