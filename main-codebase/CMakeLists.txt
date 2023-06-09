cmake_minimum_required(VERSION 3.16)
project(dyno)

set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

# Static PathORam: Time
add_executable(time_static_path_oram src/cmd/timeit/static_path_oram/time_all.cc src/static/oram/path/oram.cc)
target_link_libraries(time_static_path_oram ${CONAN_LIBS})

# Static PathOMap: Time
add_executable(time_static_path_omap src/cmd/timeit/static_path_omap/time_all.cc src/static/omap/path_avl/omap.cc src/static/oram/path/oram.cc)
target_link_libraries(time_static_path_omap ${CONAN_LIBS})

# Dynamic Stepping PathORam: Time
add_executable(time_all_but_alloc_dynamic_stepping_path_oram src/cmd/timeit/dynamic_stepping_path_oram/all_but_alloc.cc src/static/oram/path/oram.cc src/dynamic/oram/stepping_path/oram.cc)
target_link_libraries(time_all_but_alloc_dynamic_stepping_path_oram ${CONAN_LIBS})

# Dynamic Stepping PathOMap: Time
add_executable(time_all_but_alloc_dynamic_stepping_path_omap src/cmd/timeit/dynamic_stepping_path_omap/all_but_alloc.cc src/dynamic/omap/stepping_path/omap.cc src/static/omap/path_avl/omap.cc src/static/oram/path/oram.cc)
target_link_libraries(time_all_but_alloc_dynamic_stepping_path_omap ${CONAN_LIBS})

# Static PathOHeap: Time
add_executable(time_static_path_oheap src/cmd/timeit/static_path_oheap/time_all.cc src/static/oheap/path/oheap.cc)
target_link_libraries(time_static_path_oheap ${CONAN_LIBS})

# Dynamic Stepping PathOHeap: Time
add_executable(time_all_but_alloc_dynamic_stepping_path_oheap src/cmd/timeit/dynamic_stepping_path_oheap/all_but_alloc.cc src/dynamic/oheap/stepping_path/oheap.cc src/static/oheap/path/oheap.cc)
target_link_libraries(time_all_but_alloc_dynamic_stepping_path_oheap ${CONAN_LIBS})

# Print Headers
add_executable(print_csv_headers src/cmd/timeit/print_headers.cc)

# Resizable Tree ORAM Sim
add_executable(resizable_tree_oram_sim src/cmd/timeit/resizable_tree_oram_sim.cc)
target_link_libraries(resizable_tree_oram_sim ${CONAN_LIBS})
