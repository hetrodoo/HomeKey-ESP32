#pragma once

#include "soc/soc_caps.h"
#include "sdkconfig.h"
#if CONFIG_ZB_ENABLED

#include "ZigbeeEP.h"
#include "ha/esp_zigbee_ha_standard.h"

class ZigbeeDoorLock : public ZigbeeEP {
public:
    ZigbeeDoorLock(uint8_t endpoint);
    ~ZigbeeDoorLock() {}

    void onDoorCmd(void (*callback)(esp_zb_zcl_door_lock_cmd_id_t)) {
        _on_door_cmd = callback;
    }

    bool setLockState(bool state);

private:
    void zbDoorLockCmd(const esp_zb_zcl_door_lock_lock_door_message_t *message) override;
    void (*_on_door_cmd)(esp_zb_zcl_door_lock_cmd_id_t);
};

#endif  // CONFIG_ZB_ENABLED
