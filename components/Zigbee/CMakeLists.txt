FILE(GLOB_RECURSE app_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.*)

idf_component_register(
    SRCS ${app_sources}
    REQUIRES arduino-esp32 esp-zboss-lib esp-zigbee-lib app_update
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src)