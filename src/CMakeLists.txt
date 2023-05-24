find_package(Seastar REQUIRED)
find_package(Boost REQUIRED
  COMPONENTS
    iostreams
    locale
    outcome
    unit_test_framework
    uuid)
find_package(absl REQUIRED)
add_subdirectory(v)
add_subdirectory(go/kreq-gen)
