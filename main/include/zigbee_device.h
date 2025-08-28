//
// Created by hetro on 25/08/2025.
//

#ifndef HOMEKEY_ESP32_ZIGBEE_DEVICE_H
#define HOMEKEY_ESP32_ZIGBEE_DEVICE_H
#define ZIGBEE_DOOR_LOCK_ENDPOINT 10
#define BINARY_ENDPOINT_NUMBER 11
#define BINARY_2_ENDPOINT_NUMBER 12
#include "Zigbee.h"
#include "tasker.h"

inline auto zbDoorLock = ZigbeeDoorLock(ZIGBEE_DOOR_LOCK_ENDPOINT);
inline auto zbBinary = ZigbeeBinary(BINARY_ENDPOINT_NUMBER);

inline void handle_door_cmd(const esp_zb_zcl_door_lock_cmd_id_t value) {
    const auto TAG = "handle_door_cmd";
    LOG(I, "Received zigbee command: %d", value);
    run_task(TRY_UNLOCK_TASK);
}

inline void setup_zigbee() {
    const auto TAG = "setup_zigbee";

    zbDoorLock.setManufacturerAndModel("hetrodo", "HTDLockZB");
    zbBinary.setManufacturerAndModel("hetrodo", "HTDLockZB");

    zbDoorLock.onDoorCmd(handle_door_cmd);

    LOG(I, "Adding ZigbeeDoorLock endpoint to Zigbee Core");
    Zigbee.addEndpoint(&zbDoorLock);

    LOG(I, "Adding ZigbeeBinary endpoint to Zigbee Core");
    zbBinary.addBinaryInput();
    zbBinary.setBinaryInputApplication(BINARY_INPUT_APPLICATION_TYPE_SECURITY_OTHER);
    zbBinary.setBinaryInputDescription("Is Closed");
    Zigbee.addEndpoint(&zbBinary);

    if (!Zigbee.begin()) {
        LOG(E, "Zigbee failed to start!");
        LOG(E, "Rebooting...");
        ESP.restart();
    }

    LOG(I, "Connecting to network");
    while (!Zigbee.connected()) {
        LOG(I, "Waiting...");
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    run_task(UPDATE_LOCK_STATE_TASK);
    run_task(HARDWARE_TASK);
}

#endif //HOMEKEY_ESP32_ZIGBEE_DEVICE_H