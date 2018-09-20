cmake_minimum_required (VERSION 2.8)
project (ble_scan_test)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(BLUETOOTH REQUIRED)
add_executable(ble_scan_test main.cc)

target_include_directories(ble_scan_test PRIVATE ${LIBBLUETOOTH_INCLUDE_DIR})
target_link_libraries(ble_scan_test ${LIBBLUETOOTH_LIBRARIES})

install(TARGETS ble_scan_test DESTINATION bin)
