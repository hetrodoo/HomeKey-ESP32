//
// Created by hetro on 25/08/2025.
//

#ifndef HOMEKEY_ESP32_TASKER_H
#define HOMEKEY_ESP32_TASKER_H

enum Task {
    NFC_RETRY_TASK,
    NFC_POLL_TASK,
    HARDWARE_TASK,
    SETUP_HOMESPAN_TASK,
    RESTART_TASK,
    TRY_UNLOCK_TASK,
};

inline TaskHandle_t nfc_retry_task = nullptr;
inline TaskHandle_t nfc_poll_task = nullptr;
inline TaskHandle_t hardware_task = nullptr;
inline TaskHandle_t setup_homespan_task = nullptr;
inline TaskHandle_t restart_task = nullptr;
inline TaskHandle_t try_unlock_task = nullptr;

void nfc_retry_task_entry(void *arg);
[[noreturn]] void nfc_poll_task_entry(void *arg);
[[noreturn]] void hardware_task_entry(void *arg);
[[noreturn]] void restart_task_entry(void *arg);
[[noreturn]] void setup_homespan_task_entry(void *arg);
void try_unlock_task_entry(void *arg);

inline void run_task(const Task task) {
    switch (task) {
        case NFC_RETRY_TASK:
            xTaskCreate(nfc_retry_task_entry, "nfc_retry_task", 8192, nullptr, 1, &nfc_retry_task);
            break;
        case NFC_POLL_TASK:
            xTaskCreate(nfc_poll_task_entry, "nfc_poll_task", 8192, nullptr, 1, &nfc_poll_task);
            break;
        case HARDWARE_TASK:
            xTaskCreate(hardware_task_entry, "hardware_task", 8192, nullptr, 1, &hardware_task);
            break;
        case SETUP_HOMESPAN_TASK:
            xTaskCreate(setup_homespan_task_entry, "setup_homespan_task", 8192, nullptr, 1, &setup_homespan_task);
            break;
        case RESTART_TASK:
            xTaskCreate(restart_task_entry, "restart_task", 8192, nullptr, 1, &restart_task);
            break;
        case TRY_UNLOCK_TASK:
            xTaskCreate(try_unlock_task_entry, "try_unlock_task", 8192, nullptr, 1, &try_unlock_task);
            break;
    }
}

#endif //HOMEKEY_ESP32_TASKER_H