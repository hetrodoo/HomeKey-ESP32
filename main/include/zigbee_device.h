//
// Created by hetro on 25/08/2025.
//

#ifndef HOMEKEY_ESP32_ZIGBEE_DEVICE_H
#define HOMEKEY_ESP32_ZIGBEE_DEVICE_H
#define ZIGBEE_DOOR_LOCK_ENDPOINT 10
#define CONTACT_SWITCH_ENDPOINT_NUMBER 11
#include "Zigbee.h"
#include "tasker.h"

auto zbDoorLock = ZigbeeDoorLock(ZIGBEE_DOOR_LOCK_ENDPOINT);
auto zbContactSwitch = ZigbeeContactSwitch(CONTACT_SWITCH_ENDPOINT_NUMBER);

inline void handle_door_cmd(const esp_zb_zcl_door_lock_cmd_id_t value) {
    const auto TAG = "handle_door_cmd";
    LOG(I, "Received door command: %d", value);

    if (value == ESP_ZB_ZCL_CMD_DOOR_LOCK_UNLOCK_DOOR) {
        run_task(TRY_UNLOCK_TASK);
    }
}

inline void setup_zigbee() {
    const auto TAG = "setup_zigbee";

    zbDoorLock.setManufacturerAndModel("hetrodo", "HTDLockZB");
    zbContactSwitch.setManufacturerAndModel("hetrodo", "HTDLockZB");

    zbDoorLock.onDoorCmd(handle_door_cmd);

    LOG(I, "Adding ZigbeeDoorLock endpoint to Zigbee Core");
    Zigbee.addEndpoint(&zbDoorLock);

    LOG(I, "Adding ZigbeeContactSwitch endpoint to Zigbee Core");
    Zigbee.addEndpoint(&zbContactSwitch);

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

    vTaskDelay(250 / portTICK_PERIOD_MS);
    zbDoorLock.setLockState(false);
    vTaskDelay(250 / portTICK_PERIOD_MS);
    zbDoorLock.setLockState(true);

    run_task(HARDWARE_TASK);
}

#endif //HOMEKEY_ESP32_ZIGBEE_DEVICE_H