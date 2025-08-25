//
// Created by hetro on 25/08/2025.
//

#ifndef HOMEKEY_ESP32_KEYS_H
#define HOMEKEY_ESP32_KEYS_H
#include "tasker.h"

inline readerData_t readerData;
inline nlohmann::json acl;
inline nlohmann::json keys;

inline bool write_json_key() {
    const auto TAG = "write_json_key";

    if (keys == nullptr && restart_task == nullptr) {
        run_task(RESTART_TASK);
    }

    if (FILE* f = fopen("/spiffs/key.json", "w"); f != nullptr) {
        const nlohmann::json keys = readerData;
        const std::string json_string = keys.dump();

        fwrite(json_string.c_str(), 1, json_string.length(), f);
        fclose(f);

        LOG(I, "Successfully written to file.");
        return true;
    }

    LOG(E, "Failed to open file for writing.");
    return false;
}

inline nlohmann::json read_json_file(const char *path) {
    const auto TAG = "read_json_file";

    if (FILE* f = fopen(path, "r"); f != nullptr) {
        fseek(f, 0, SEEK_END);
        const long size = ftell(f);
        rewind(f);

        const auto buffer = static_cast<char *>(malloc(size + 1));

        if (buffer == nullptr) {
            LOG(E, "Failed to allocate buffer");
            fclose(f);
            return nullptr;
        }

        fread(buffer, 1, size, f);
        buffer[size] = '\0';
        fclose(f);

        LOG(I, "Read '%ld' chars from file.", size);
        const auto keys = nlohmann::json::parse(buffer);
        free(buffer);

        if (keys.is_discarded())
        {
            LOG(E, "Read invalid json content, aborting!");
            return nullptr;
        }

        return keys;
    }

    LOG(E, "Failed to open file for reading.");
    return nullptr;
}

inline void delete_json_key()
{
    if (const int ret = unlink("/spiffs/key.json"); ret == 0) {
        printf("Deleted key successfully.\n");
    } else {
        printf("Failed to delete key file. Error: %d\n", ret);
    }

    readerData.issuers.clear();
    readerData.reader_gid.clear();
    readerData.reader_id.clear();
    readerData.reader_pk.clear();
    readerData.reader_pk_x.clear();
    readerData.reader_sk.clear();
}

inline void setup_spiffs() {
    const auto TAG = "setup_spiffs";

    constexpr esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = nullptr,
        .max_files = 5,
        .format_if_mount_failed = false
      };

    if (const esp_err_t ret = esp_vfs_spiffs_register(&conf); ret != ESP_OK) {
        LOG(E, "Failed to mount SPIFFS (%s)", esp_err_to_name(ret));
        return;
    }

    size_t total = 0, used = 0;
    esp_spiffs_info(nullptr, &total, &used);
    LOG(I, "Total: %d, Used: %d", total, used);
}

#endif //HOMEKEY_ESP32_KEYS_H