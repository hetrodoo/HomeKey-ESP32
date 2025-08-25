idf_component_register(SRCS "main.cpp"
                    INCLUDE_DIRS "include"
                    REQUIRES app_update esp-zboss-lib esp-zigbee-lib Zigbee HomeSpan PN532 HK-HomeKit-Lib libsodium spiffs)

spiffs_create_partition_image(spiffs ${CMAKE_CURRENT_SOURCE_DIR}/spiffs_data FLASH_IN_PROJECT)
