#include <cstdint>
#include <memory>
#define JSON_NOEXCEPTION 1
#include <sodium/crypto_sign.h>
#include <sodium/crypto_box.h>
#include "HAP.h"
#include "hkAuthContext.h"
#include "HomeKey.h"
#include "array"
#include "logging.h"
#include "PN532_SPI.h"
#include "PN532.h"
#include "chrono"
#include "HK_HomeKit.h"
#include "helper.h"
#include "esp_app_desc.h"
#include "pins_arduino.h"
#include "NFC_SERV_CHARS.h"
#include <mbedtls/sha256.h>
#include <esp_mac.h>
#include <esp_spiffs.h>

auto TAG = "MAIN";

PN532_SPI *pn532spi;
PN532 *nfc;
TaskHandle_t nfc_reconnect_task = nullptr;
TaskHandle_t nfc_poll_task = nullptr;
TaskHandle_t serial_poll_task = nullptr;

readerData_t readerData;
KeyFlow hkFlow = kFlowFAST;
uint8_t ecpData[18] = {0x6A, 0x2, 0xCB, 0x2, 0x6, 0x2, 0x11, 0x0};
const std::array<std::array<uint8_t, 6>, 4> hk_color_vals = {{{0x01, 0x04, 0xce, 0xd5, 0xda, 0x00}, {0x01, 0x04, 0xaa, 0xd6, 0xec, 0x00}, {0x01, 0x04, 0xe3, 0xe3, 0xe3, 0x00}, {0x01, 0x04, 0x00, 0x00, 0x00, 0x00}}};

void gnd_pulse_pin(const uint8_t pin, const TickType_t period = 150) {
  digitalWrite(pin, LOW);
  vTaskDelay(period / portTICK_PERIOD_MS);
  digitalWrite(pin, HIGH);
}

std::string hex_representation(const std::vector<uint8_t> &v)
{
  std::string hex_tmp;
  for (const auto x : v)
  {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(x);
    hex_tmp += oss.str();
  }
  return hex_tmp;
}


void setup_spiffs() {
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

nlohmann::json read_json_key() {
  const auto TAG = "read_json_key";

  if (FILE* f = fopen("/spiffs/key.json", "r"); f != nullptr) {
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    rewind(f);

    const auto buffer = static_cast<char *>(malloc(size + 1));

    if (buffer == nullptr) {
      LOG(E, "Failed to allocate buffer");
      fclose(f);
      abort();
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
      abort();
    }

    return keys;
  }

  LOG(E, "Failed to open file for reading.");
  abort();
}

void write_json_key() {
  const auto TAG = "write_json_key";

  if (FILE* f = fopen("/spiffs/key.json", "w"); f != nullptr) {
    const nlohmann::json keys = readerData;
    const std::string json_string = keys.dump();

    fwrite(json_string.c_str(), 1, json_string.length(), f);
    fclose(f);

    LOG(I, "Successfully written to file.");
    return;
  }

  LOG(E, "Failed to open file for writing.");
  abort();
}

void nfc_retry(void *arg)
{
  const auto TAG = "nfc_retry";

  LOG(I, "Starting reconnecting PN532");
  while (true)
  {
    nfc->begin();
    if (const uint32_t version_data = nfc->getFirmwareVersion(); !version_data)
    {
      LOG(E, "Error establishing PN532 connection");
    }
    else
    {
      const unsigned int model = (version_data >> 24) & 0xFF;
      LOG(I, "Found chip PN5%x", model);
      const int maj = (version_data >> 16) & 0xFF;
      const int min = (version_data >> 8) & 0xFF;
      LOG(I, "Firmware ver. %d.%d", maj, min);
      nfc->SAMConfig();
      nfc->setRFField(0x02, 0x01);
      nfc->setPassiveActivationRetries(0);
      LOG(I, "Waiting for an ISO14443A card");
      vTaskResume(nfc_poll_task);
      vTaskDelete(nullptr);
      return;
    }
    nfc->stop();
    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
}

[[noreturn]] void nfc_thread_entry(void *arg) {
  const auto TAG = "nfc_thread_entry";

  if (uint32_t version_data = nfc->getFirmwareVersion(); !version_data)
  {
    LOG(E, "Error establishing PN532 connection");
    nfc->stop();
    xTaskCreate(nfc_retry, "nfc_reconnect_task", 8192, nullptr, 1, &nfc_reconnect_task);
    vTaskSuspend(nullptr);
  }
  else
  {
    unsigned int model = (version_data >> 24) & 0xFF;
    LOG(I, "Found chip PN5%x", model);
    int maj = (version_data >> 16) & 0xFF;
    int min = (version_data >> 8) & 0xFF;
    LOG(I, "Firmware ver. %d.%d", maj, min);
    nfc->SAMConfig();
    nfc->setRFField(0x02, 0x01);
    nfc->setPassiveActivationRetries(0);
    LOG(I, "Waiting for an ISO14443A card");
  }

  memcpy(ecpData + 8, readerData.reader_gid.data(), readerData.reader_gid.size());
  with_crc16(ecpData, 16, ecpData + 16);

  while (true)
  {
    uint8_t res[4];
    uint16_t resLen = 4;

    if (bool write_status = nfc->writeRegister(0x633d, 0, true); !write_status)
    {
      LOG(W, "writeRegister has failed, abandoning ship !!");
      nfc->stop();
      xTaskCreate(nfc_retry, "nfc_reconnect_task", 8192, nullptr, 1, &nfc_reconnect_task);
      vTaskSuspend(nullptr);
    }

    nfc->inCommunicateThru(ecpData, sizeof(ecpData), res, &resLen, 100, true);
    uint8_t uid[16];
    uint8_t uidLen = 0;
    uint8_t atqa[2];
    uint8_t sak[1];

    if (nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, atqa, sak, 500, true, true))
    {
      nfc->setPassiveActivationRetries(5);
      LOG(D, "ATQA: %02x", atqa[0]);
      LOG(D, "SAK: %02x", sak[0]);
      ESP_LOG_BUFFER_HEX_LEVEL(TAG, uid, uidLen, ESP_LOG_VERBOSE);
      LOG(I, "*** PASSIVE TARGET DETECTED ***");
      auto startTime = std::chrono::high_resolution_clock::now();
      uint8_t data[13] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x08, 0x58, 0x01, 0x01, 0x0};
      uint8_t selectCmdRes[9];
      uint16_t selectCmdResLength = 9;
      LOG(I, "Requesting supported HomeKey versions");
      LOG(D, "SELECT HomeKey Applet, APDU: ");
      ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, sizeof(data), ESP_LOG_VERBOSE);
      bool status = nfc->inDataExchange(data, sizeof(data), selectCmdRes, &selectCmdResLength);
      LOG(D, "SELECT HomeKey Applet, Response");
      ESP_LOG_BUFFER_HEX_LEVEL(TAG, selectCmdRes, selectCmdResLength, ESP_LOG_VERBOSE);
      if (status && selectCmdRes[selectCmdResLength - 2] == 0x90 && selectCmdRes[selectCmdResLength - 1] == 0x00)
      {
        LOG(D, "*** SELECT HOMEKEY APPLET SUCCESSFUL ***");
        LOG(D, "Reader Private Key: %s", red_log::bufToHexString(readerData.reader_pk.data(), readerData.reader_pk.size()).c_str());

        auto nfcCallback = [](std::vector<uint8_t> &send, std::vector<uint8_t> &recv, bool inList) -> bool
        {
          uint16_t recvLen = 256;
          recv.resize(recvLen);

          const bool result = nfc->inDataExchange(send.data(), static_cast<uint8_t>(send.size()), recv.data(), &recvLen, inList);

          recv.resize(recvLen);
          return result;
        };

        HKAuthenticationContext authCtx(nfcCallback, readerData, write_json_key);

        if (auto auth_result = authCtx.authenticate(hkFlow); std::get<2>(auth_result) != kFlowFailed)
        {
          nlohmann::json payload;
          payload["issuer_id"] = hex_representation(std::get<0>(auth_result));
          payload["endpoint_id"] = hex_representation(std::get<1>(auth_result));
          payload["reader_id"] = hex_representation(readerData.reader_id);
          payload["home_key"] = true;
          std::string payloadStr = payload.dump();

          LOG(I, "Apple HomeKey success!, payload: %s", payloadStr.c_str());

          gnd_pulse_pin(GPIO_NUM_21);
          gnd_pulse_pin(GPIO_NUM_20, 2500);

          auto stopTime = std::chrono::high_resolution_clock::now();
          LOG(I, "Total Time (detection->auth->gpio->mqtt): %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
        }

        nfc->setRFField(0x02, 0x01);
      }
      else
      {
        LOG(W, "Invalid Response, probably not HomeKey, publishing target's UID");

        nlohmann::json payload;
        payload["atqa"] = hex_representation(std::vector<uint8_t>(atqa, atqa + 2));
        payload["sak"] = hex_representation(std::vector<uint8_t>(sak, sak + 1));
        payload["uid"] = hex_representation(std::vector<uint8_t>(uid, uid + uidLen));
        payload["home_key"] = false;
        std::string payload_dump = payload.dump();

        LOG(I, "NON Apple HomeKey TAG SCANNED, payload: %s", payload_dump.c_str());
        // TODO: handle non-home_key tag
      }
      vTaskDelay(50 / portTICK_PERIOD_MS);
      nfc->inRelease();
      int counter = 50;
      bool deviceStillInField = nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen);
      LOG(D, "Target still present: %d", deviceStillInField);
      while (deviceStillInField)
      {
        if (counter == 0)
          break;
        vTaskDelay(50 / portTICK_PERIOD_MS);
        nfc->inRelease();
        deviceStillInField = nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen);
        --counter;
        LOG(D, "Target still present: %d Counter=%d", deviceStillInField, counter);
      }
      nfc->inRelease();
      nfc->setPassiveActivationRetries(0);
    }
    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
}

[[noreturn]] void serial_thread_entry(void *arg) {
  while (true)
  {
    if (Serial.available())
    {
      const auto TAG = "serial_thread_entry";

      std::string input = Serial.readStringUntil('\n').c_str();
      LOG(I, "Received command: %s", input.c_str());

      if (input == "write")
      {
        write_json_key();
        LOG(I, "Ok.");
      }

      if (input == "read")
      {
        LOG(I, "%s", read_json_key().dump().c_str());
      }
    }

    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
}

void setup()
{
  const auto TAG = "SETUP";

  pinMode(GPIO_NUM_20, OUTPUT);
  digitalWrite(GPIO_NUM_20, HIGH);

  pinMode(GPIO_NUM_21, OUTPUT);
  digitalWrite(GPIO_NUM_21, HIGH);

  Serial.begin(115200);
  //while (!Serial) {}
  vTaskDelay(1000 / portTICK_PERIOD_MS);

  setup_spiffs();

  read_json_key().get_to<readerData_t>(readerData);
  LOG(I, "Reader Data loaded from spiffs.");

  pn532spi = new PN532_SPI(GPIO_NUM_7, GPIO_NUM_4, GPIO_NUM_5, GPIO_NUM_6);
  nfc = new PN532(*pn532spi);
  nfc->begin();

  LOG(I, "READER GROUP ID (%d): %s", readerData.reader_gid.size(), red_log::bufToHexString(readerData.reader_gid.data(), readerData.reader_gid.size()).c_str());
  LOG(I, "READER UNIQUE ID (%d): %s", readerData.reader_id.size(), red_log::bufToHexString(readerData.reader_id.data(), readerData.reader_id.size()).c_str());

  LOG(I, "HOMEKEY ISSUERS: %d", readerData.issuers.size());

  for (auto &&issuer : readerData.issuers)
  {
    LOG(D, "Issuer ID: %s, Public Key: %s", red_log::bufToHexString(issuer.issuer_id.data(), issuer.issuer_id.size()).c_str(), red_log::bufToHexString(issuer.issuer_pk.data(), issuer.issuer_pk.size()).c_str());
  }

  xTaskCreate(serial_thread_entry, "serial_task", 8192, nullptr, 1, &serial_poll_task);
  xTaskCreate(nfc_thread_entry, "nfc_task", 8192, nullptr, 1, &nfc_poll_task);
}

void loop()
{
  vTaskDelay(5 / portTICK_PERIOD_MS);
}
