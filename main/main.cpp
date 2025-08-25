#define ZIGBEE_DOOR_LOCK_ENDPOINT 10
#define CONTACT_SWITCH_ENDPOINT_NUMBER 11
#define JSON_NOEXCEPTION 1

#include <cstdint>
#include <memory>
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
#include "tasker.h"
#include "keys.h"
#include "zigbee_device.h"
#include "homespan_device.h"

uint8_t sigPin = GPIO_NUM_14;
uint8_t sensorPin = GPIO_NUM_11;

PN532_SPI *pn532spi;
PN532 *nfc;

KeyFlow hkFlow = kFlowFAST;

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

bool auth_raw_uid(const std::string &uid) {
  if (!acl.is_array()) {
    return false;
  }

  return std::ranges::any_of(acl, [uid](const auto& entry) {
    return entry.is_string() && entry.template get<std::string>() == uid;
  });
}

void nfc_retry_task_entry(void *arg)
{
  const auto TAG = "nfc_retry_entry";
  LOG(I, "Running...");

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
      const uint32_t maj = (version_data >> 16) & 0xFF;
      const uint32_t min = (version_data >> 8) & 0xFF;
      LOG(I, "Firmware ver. %lu.%lu", maj, min);
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

[[noreturn]] void nfc_poll_task_entry(void *arg) {
  const auto TAG = "nfc_task_entry";
  LOG(I, "Running...");

  if (uint32_t version_data = nfc->getFirmwareVersion(); !version_data)
  {
    LOG(E, "Error establishing PN532 connection");
    nfc->stop();
    run_task(NFC_RETRY_TASK);
    vTaskSuspend(nullptr);
  }
  else
  {
    unsigned int model = (version_data >> 24) & 0xFF;
    LOG(I, "Found chip PN5%x", model);
    uint32_t maj = (version_data >> 16) & 0xFF;
    uint32_t min = (version_data >> 8) & 0xFF;
    LOG(I, "Firmware ver. %lu.%lu", maj, min);
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
      run_task(NFC_RETRY_TASK);
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
          run_task(TRY_UNLOCK_TASK);

          auto stopTime = std::chrono::high_resolution_clock::now();
          LOG(I, "Total Time (detection->auth->gpio->mqtt): %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
        }

        nfc->setRFField(0x02, 0x01);
      }
      else {
        LOG(W, "Invalid Response, probably not Apple HomeKey.");

        nlohmann::json payload;
        payload["atqa"] = hex_representation(std::vector<uint8_t>(atqa, atqa + 2));
        payload["sak"] = hex_representation(std::vector<uint8_t>(sak, sak + 1));
        payload["uid"] = hex_representation(std::vector<uint8_t>(uid, uid + uidLen));
        payload["home_key"] = false;
        LOG(I, "Tag payload %s.", payload.dump().c_str());

        if (auth_raw_uid(payload["uid"])) {
          LOG(I, "Raw tag uid found in acl.");
          run_task(TRY_UNLOCK_TASK);
        } else {
          LOG(E, "UID was not on acl. ignoring...");
        }
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

[[noreturn]] void hardware_task_entry(void *arg) {
  const auto TAG = "hardware_task_entry";
  LOG(I, "Running...");

  while (true) {
    static bool contact = false;

    if (digitalRead(sensorPin) == HIGH && !contact) {
      zbContactSwitch.setOpen();
      contact = true;
    } else if (digitalRead(sensorPin) == LOW && contact) {
      zbContactSwitch.setClosed();
      contact = false;
    }

    if (digitalRead(BOOT_PIN) == LOW) {
      const unsigned long startTime = millis();

      while (digitalRead(BOOT_PIN) == LOW) {
        vTaskDelay(50 / portTICK_PERIOD_MS);
        if ((millis() - startTime) > 3000) {

          LOG(I, "Clearing Homekey Keys...");
          delete_json_key();

          LOG(I, "Resetting zigbee to factory...");
          Zigbee.factoryReset();
        }
      }
    }

    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
}

[[noreturn]] void restart_task_entry(void *arg) {
  const auto TAG = "restart_task_entry";
  LOG(I, "Running...");

  constexpr auto restart_in = 10;

  for (int i = 0; i < restart_in; i++) {
    LOG(I, "Restarting in %d...", restart_in - i);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  LOG(I, "Restarting");
  esp_restart();
}

[[noreturn]] void setup_homespan_task_entry(void *arg) {
  const auto TAG = "setup_homespan_task_entry";
  LOG(I, "Running...");

  setup_homespan();

  while (true) {
    homeSpan.poll();
    vTaskDelay(5 / portTICK_PERIOD_MS);
  }
}

void try_unlock_task_entry(void *arg) {
  const auto TAG = "try_unlock";

  LOG(I, "Trying...");
  digitalWrite(sigPin, LOW);
  vTaskDelay(250 / portTICK_PERIOD_MS);
  digitalWrite(sigPin, HIGH);
}

void setup()
{
  const auto TAG = "SETUP";

  pinMode(sigPin, OUTPUT);
  digitalWrite(sigPin, HIGH);

  pinMode(BOOT_PIN, INPUT_PULLUP);
  pinMode(sensorPin, INPUT_PULLUP);

  Serial.begin(115200);
  vTaskDelay(1000 / portTICK_PERIOD_MS);

  setup_spiffs();

  //Homekey
  acl = read_json_file("/spiffs/acl.json");
  keys = read_json_file("/spiffs/key.json");

  if (keys != nullptr) {
    keys.get_to<readerData_t>(readerData);
    LOG(I, "Reader Data loaded from spiffs.");

    pn532spi = new PN532_SPI(SS, SCK, MISO, MOSI);
    nfc = new PN532(*pn532spi);
    nfc->begin();

    LOG(I, "READER GROUP ID (%d): %s", readerData.reader_gid.size(), red_log::bufToHexString(readerData.reader_gid.data(), readerData.reader_gid.size()).c_str());
    LOG(I, "READER UNIQUE ID (%d): %s", readerData.reader_id.size(), red_log::bufToHexString(readerData.reader_id.data(), readerData.reader_id.size()).c_str());

    LOG(I, "HOMEKEY ISSUERS: %d", readerData.issuers.size());

    for (auto &&issuer : readerData.issuers)
    {
      LOG(D, "Issuer ID: %s, Public Key: %s", red_log::bufToHexString(issuer.issuer_id.data(), issuer.issuer_id.size()).c_str(), red_log::bufToHexString(issuer.issuer_pk.data(), issuer.issuer_pk.size()).c_str());
    }

    run_task(NFC_POLL_TASK);
    setup_zigbee();
  } else {
    LOG(E, "Key json not found, going HomeSpan route...");
    run_task(SETUP_HOMESPAN_TASK);
  }
}

void loop() {}
