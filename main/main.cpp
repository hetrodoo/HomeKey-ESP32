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

auto DEFAULT_JSON_KEY = R"({"group_identifier":[158,246,200,87,37,152,247,177],"issuers":[{"endpoints":[{"counter":0,"endpointId":[108,36,181,69,63,214],"endpoint_key_x":[167,185,172,64,82,77,72,18,248,111,22,219,170,243,55,244,209,176,150,249,173,120,61,149,244,167,116,46,222,165,60,60],"key_type":2,"last_used_at":0,"persistent_key":[199,19,161,188,229,145,93,76,14,238,163,108,36,44,248,175,179,183,146,242,124,218,151,35,229,239,199,27,122,83,2,95],"publicKey":[4,167,185,172,64,82,77,72,18,248,111,22,219,170,243,55,244,209,176,150,249,173,120,61,149,244,167,116,46,222,165,60,60,135,98,69,140,123,129,11,95,68,93,57,249,163,118,219,252,19,220,158,108,76,126,206,153,95,81,63,214,181,16,39,133]},{"counter":0,"endpointId":[224,109,202,183,44,7],"endpoint_key_x":[237,84,155,25,167,29,145,242,46,100,20,0,33,73,253,187,127,148,213,127,60,194,131,222,250,215,194,29,34,233,164,76],"key_type":0,"last_used_at":0,"persistent_key":[226,132,57,216,190,24,105,86,250,60,49,29,171,26,107,20,129,131,113,254,140,90,58,7,148,249,25,198,29,190,87,131],"publicKey":[4,237,84,155,25,167,29,145,242,46,100,20,0,33,73,253,187,127,148,213,127,60,194,131,222,250,215,194,29,34,233,164,76,59,120,91,136,6,227,194,71,161,150,65,38,43,159,227,36,183,50,107,210,59,129,184,71,72,141,125,201,15,12,136,184]}],"issuerId":[30,101,118,48,236,61,170,91],"issuer_key_x":[],"publicKey":[160,75,154,41,88,32,7,2,137,75,122,66,206,177,242,39,38,111,146,128,185,63,93,142,81,255,200,242,182,62,223,179]}],"reader_key_x":[236,208,254,13,165,37,140,252,182,115,6,141,12,251,212,50,27,219,230,141,248,58,27,20,234,253,12,53,138,140,231,51],"reader_private_key":[187,194,224,41,25,135,202,213,137,179,58,3,228,2,83,145,34,49,61,22,167,215,201,140,58,145,119,98,74,175,167,134],"reader_public_key":[4,236,208,254,13,165,37,140,252,182,115,6,141,12,251,212,50,27,219,230,141,248,58,27,20,234,253,12,53,138,140,231,51,186,40,8,57,202,157,188,185,110,200,105,140,255,214,101,36,166,73,198,21,11,255,54,96,244,17,75,62,20,140,74,191],"unique_identifier":[43,98,33,12,217,236,81,3]})";
auto TAG = "MAIN";

PN532_SPI *pn532spi;
PN532 *nfc;
TaskHandle_t nfc_reconnect_task = nullptr;
TaskHandle_t nfc_poll_task = nullptr;
TaskHandle_t serial_poll_task = nullptr;

nvs_handle savedData;
readerData_t readerData;
KeyFlow hkFlow = kFlowFAST;
uint8_t ecpData[18] = {0x6A, 0x2, 0xCB, 0x2, 0x6, 0x2, 0x11, 0x0};
const std::array<std::array<uint8_t, 6>, 4> hk_color_vals = {{{0x01, 0x04, 0xce, 0xd5, 0xda, 0x00}, {0x01, 0x04, 0xaa, 0xd6, 0xec, 0x00}, {0x01, 0x04, 0xe3, 0xe3, 0xe3, 0x00}, {0x01, 0x04, 0x00, 0x00, 0x00, 0x00}}};

std::string hex_representation(const std::vector<uint8_t> &v)
{
  std::string hex_tmp;
  for (auto x : v)
  {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(x);
    hex_tmp += oss.str();
  }
  return hex_tmp;
}

void delete_reader_data(const char *buf = "")
{
  const esp_err_t erase_nvs = nvs_erase_key(savedData, "READERDATA");
  const esp_err_t commit_nvs = nvs_commit(savedData);
  readerData.issuers.clear();
  readerData.reader_gid.clear();
  readerData.reader_id.clear();
  readerData.reader_pk.clear();
  readerData.reader_pk_x.clear();
  readerData.reader_sk.clear();
  LOG(D, "*** NVS W STATUS");
  LOG(D, "ERASE: %s", esp_err_to_name(erase_nvs));
  LOG(D, "COMMIT: %s", esp_err_to_name(commit_nvs));
  LOG(D, "*** NVS W STATUS");
}

void nfc_retry(void *arg)
{
  ESP_LOGI(TAG, "Starting reconnecting PN532");
  while (true)
  {
    nfc->begin();
    if (const uint32_t version_data = nfc->getFirmwareVersion(); !version_data)
    {
      ESP_LOGE("NFC_SETUP", "Error establishing PN532 connection");
    }
    else
    {
      const unsigned int model = (version_data >> 24) & 0xFF;
      ESP_LOGI("NFC_SETUP", "Found chip PN5%x", model);
      const int maj = (version_data >> 16) & 0xFF;
      const int min = (version_data >> 8) & 0xFF;
      ESP_LOGI("NFC_SETUP", "Firmware ver. %d.%d", maj, min);
      nfc->SAMConfig();
      nfc->setRFField(0x02, 0x01);
      nfc->setPassiveActivationRetries(0);
      ESP_LOGI("NFC_SETUP", "Waiting for an ISO14443A card");
      vTaskResume(nfc_poll_task);
      vTaskDelete(NULL);
      return;
    }
    nfc->stop();
    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
}

void nfc_thread_entry(void *arg)
{
  uint32_t versiondata = nfc->getFirmwareVersion();
  if (!versiondata)
  {
    ESP_LOGE("NFC_SETUP", "Error establishing PN532 connection");
    nfc->stop();
    xTaskCreate(nfc_retry, "nfc_reconnect_task", 8192, NULL, 1, &nfc_reconnect_task);
    vTaskSuspend(NULL);
  }
  else
  {
    unsigned int model = (versiondata >> 24) & 0xFF;
    ESP_LOGI("NFC_SETUP", "Found chip PN5%x", model);
    int maj = (versiondata >> 16) & 0xFF;
    int min = (versiondata >> 8) & 0xFF;
    ESP_LOGI("NFC_SETUP", "Firmware ver. %d.%d", maj, min);
    nfc->SAMConfig();
    nfc->setRFField(0x02, 0x01);
    nfc->setPassiveActivationRetries(0);
    ESP_LOGI("NFC_SETUP", "Waiting for an ISO14443A card");
  }
  memcpy(ecpData + 8, readerData.reader_gid.data(), readerData.reader_gid.size());
  with_crc16(ecpData, 16, ecpData + 16);
  while (1)
  {
    uint8_t res[4];
    uint16_t resLen = 4;
    bool writeStatus = nfc->writeRegister(0x633d, 0, true);
    if (!writeStatus)
    {
      LOG(W, "writeRegister has failed, abandoning ship !!");
      nfc->stop();
      xTaskCreate(nfc_retry, "nfc_reconnect_task", 8192, NULL, 1, &nfc_reconnect_task);
      vTaskSuspend(NULL);
    }
    nfc->inCommunicateThru(ecpData, sizeof(ecpData), res, &resLen, 100, true);
    uint8_t uid[16];
    uint8_t uidLen = 0;
    uint8_t atqa[2];
    uint8_t sak[1];
    bool passiveTarget = nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, atqa, sak, 500, true, true);
    if (passiveTarget)
    {
      nfc->setPassiveActivationRetries(5);
      LOG(D, "ATQA: %02x", atqa[0]);
      LOG(D, "SAK: %02x", sak[0]);
      ESP_LOG_BUFFER_HEX_LEVEL(TAG, uid, (size_t)uidLen, ESP_LOG_VERBOSE);
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

          bool result = nfc->inDataExchange(send.data(), static_cast<uint8_t>(send.size()), recv.data(), &recvLen, inList);

          recv.resize(recvLen);
          return result;
        };

        HKAuthenticationContext authCtx(nfcCallback, readerData, savedData);

        auto authResult = authCtx.authenticate(hkFlow);
        if (std::get<2>(authResult) != kFlowFailed)
        {
          json payload;
          payload["issuerId"] = hex_representation(std::get<0>(authResult));
          payload["endpointId"] = hex_representation(std::get<1>(authResult));
          payload["readerId"] = hex_representation(readerData.reader_id);
          payload["homekey"] = true;
          std::string payloadStr = payload.dump();

          // TODO: handle homekey success
          LOG(I, "HOMEKEY SUCCESS, payload: %s", payloadStr.c_str());

          auto stopTime = std::chrono::high_resolution_clock::now();
          LOG(I, "Total Time (detection->auth->gpio->mqtt): %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
        }
        else
        {
          // TODO: handle homekey failure
          LOG(W, "We got status FlowFailed, mqtt untouched!");
        }
        nfc->setRFField(0x02, 0x01);
      }
      else
      {
        LOG(W, "Invalid Response, probably not Homekey, publishing target's UID");

        json payload;
        payload["atqa"] = hex_representation(std::vector<uint8_t>(atqa, atqa + 2));
        payload["sak"] = hex_representation(std::vector<uint8_t>(sak, sak + 1));
        payload["uid"] = hex_representation(std::vector<uint8_t>(uid, uid + uidLen));
        payload["homekey"] = false;
        std::string payload_dump = payload.dump();

        LOG(I, "NON HOMEKEY TAG SCANNED, payload: %s", payload_dump.c_str());
        // TODO: handle non-homekey tag
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
  vTaskDelete(NULL);
  return;
}

void serial_thread_entry(void *arg)
{
  while (1)
  {
    if (Serial.available())
    {
      std::string input = Serial.readStringUntil('\n').c_str();
      LOG(I, "Received command: %s", input.c_str());

      if (input == "delete")
      {
        delete_reader_data(NULL);
        LOG(I, "Reader data deleted.");
        esp_restart();
      }
    }

    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
  vTaskDelete(NULL);
  return;
}

void setup()
{
  Serial.begin(115200);
  while (!Serial)
  {
    ;
  }
  vTaskDelay(1000 / portTICK_PERIOD_MS);

  const esp_app_desc_t *app_desc = esp_app_get_description();
  std::string app_version = app_desc->version;

  size_t len;
  const char *TAG = "SETUP";

  nvs_open("SAVED_DATA", NVS_READWRITE, &savedData);
  esp_err_t nvs_get_stt = nvs_get_blob(savedData, "READERDATA", NULL, &len);
  LOG(I, "Status: %s", esp_err_to_name(nvs_get_stt));

  if (nvs_get_stt == ESP_OK)
  {
    std::vector<uint8_t> savedBuf(len);
    nvs_get_blob(savedData, "READERDATA", savedBuf.data(), &len);
    LOG(D, "NVS READERDATA LENGTH: %d", len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, savedBuf.data(), savedBuf.size(), ESP_LOG_VERBOSE);
    nlohmann::json data = nlohmann::json::from_msgpack(savedBuf);

    if (data.is_discarded())
    {
      delete_reader_data(NULL);
      LOG(I, "Reader data deleted.");
      esp_restart();
    }

    data.get_to<readerData_t>(readerData);
    LOG(I, "Reader Data loaded from NVS");
    LOG(I, "Json: %s", data.dump().c_str());
  } else {
    const nlohmann::json json = nlohmann::json::parse(DEFAULT_JSON_KEY);

    if (json.is_discarded())
    {
      LOG(E, "No valid data found in NVS and default JSON is invalid, aborting!");
      abort();
    }

    const std::vector<uint8_t> data = nlohmann::json::to_msgpack(json);

    nvs_set_blob(savedData, "READERDATA", data.data(), data.size());
    nvs_commit(savedData);
    esp_restart();
  }

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
  vTaskDelay(5);
}
