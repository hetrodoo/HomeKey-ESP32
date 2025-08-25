#include "ZigbeeDoorLock.h"
#if CONFIG_ZB_ENABLED

ZigbeeDoorLock::ZigbeeDoorLock(uint8_t endpoint) : ZigbeeEP(endpoint) {
    _device_id = ESP_ZB_HA_DOOR_LOCK_DEVICE_ID;

    esp_zb_door_lock_cfg_t door_lock_cfg = ESP_ZB_DEFAULT_DOOR_LOCK_CONFIG();
    _cluster_list = esp_zb_door_lock_clusters_create(&door_lock_cfg);
    _ep_config = {.endpoint = endpoint, .app_profile_id = ESP_ZB_AF_HA_PROFILE_ID, .app_device_id = ESP_ZB_HA_DOOR_LOCK_DEVICE_ID, .app_device_version = 0};
    log_v("Door Lock endpoint created %d", _endpoint);
}

void ZigbeeDoorLock::zbDoorLockCmd(const esp_zb_zcl_door_lock_lock_door_message_t *message) {
    _on_door_cmd(message->cmd_id);
}

bool ZigbeeDoorLock::setLockState(bool isLocked) {
    esp_zb_zcl_status_t ret = ESP_ZB_ZCL_STATUS_SUCCESS;

    log_v("Updating door lock state to %d", isLocked);
    /* Update locked/unlocked state */
    esp_zb_lock_acquire(portMAX_DELAY);
    ret = esp_zb_zcl_set_attribute_val(
      _endpoint, ESP_ZB_ZCL_CLUSTER_ID_DOOR_LOCK, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE, ESP_ZB_ZCL_ATTR_DOOR_LOCK_LOCK_STATE_ID, &isLocked, false
    );
    esp_zb_lock_release();

    if (ret != ESP_ZB_ZCL_STATUS_SUCCESS) {
        Serial.print("Failed to set current state: ");
        Serial.println(esp_zb_zcl_status_to_name(ret));

        log_e("Failed to set light state: 0x%x: %s", ret, esp_zb_zcl_status_to_name(ret));
        return false;
    }
    return true;
}

#endif  // CONFIG_ZB_ENABLED
