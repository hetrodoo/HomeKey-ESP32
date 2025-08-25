#define ZIGBEE_DOOR_LOCK_ENDPOINT 10
#define CONTACT_SWITCH_ENDPOINT_NUMBER 11

#include <cstdint>
#include <memory>
#define JSON_NOEXCEPTION 1
#include <sodium/crypto_sign.h>
#include <sodium/crypto_box.h>
#include "HAP.h"
#include "hkAuthContext.h"
#include "HomeKey.h"
#include "array"
#include "HomeSpan.h"
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
#include "Zigbee.h"

auto TAG = "MAIN";
bool write_json_key();
[[noreturn]] void restart_task_entry(void *arg);

uint8_t sigPin = GPIO_NUM_14;
uint8_t sensorPin = GPIO_NUM_11;

auto zbDoorLock = ZigbeeDoorLock(ZIGBEE_DOOR_LOCK_ENDPOINT);
auto zbContactSwitch = ZigbeeContactSwitch(CONTACT_SWITCH_ENDPOINT_NUMBER);

nlohmann::json acl;
nlohmann::json keys;
PN532_SPI *pn532spi;
PN532 *nfc;
TaskHandle_t nfc_reconnect_task = nullptr;
TaskHandle_t nfc_poll_task = nullptr;
TaskHandle_t hardware_task = nullptr;
TaskHandle_t restart_task = nullptr;
TaskHandle_t setup_homespan_task = nullptr;

readerData_t readerData;
KeyFlow hkFlow = kFlowFAST;
SpanCharacteristic *lockCurrentState;
SpanCharacteristic *lockTargetState;
uint8_t ecpData[18] = {0x6A, 0x2, 0xCB, 0x2, 0x6, 0x2, 0x11, 0x0};
const std::array<std::array<uint8_t, 6>, 4> hk_color_vals = {{{0x01, 0x04, 0xce, 0xd5, 0xda, 0x00}, {0x01, 0x04, 0xaa, 0xd6, 0xec, 0x00}, {0x01, 0x04, 0xe3, 0xe3, 0xe3, 0x00}, {0x01, 0x04, 0x00, 0x00, 0x00, 0x00}}};

struct LockManagement final : Service::LockManagement
{
  SpanCharacteristic *lockControlPoint;
  SpanCharacteristic *version;
  const char *TAG = "LockManagement";

  LockManagement() : Service::LockManagement()
  {
    LOG(I, "Configuring LockManagement");

    lockControlPoint = new Characteristic::LockControlPoint();
    version = new Characteristic::Version();

  }

};

struct NFCAccessoryInformation final : Service::AccessoryInformation
{
  const char *TAG = "NFCAccessoryInformation";

  NFCAccessoryInformation() : Service::AccessoryInformation()
  {

    LOG(I, "Configuring NFCAccessoryInformation"); // initialization message

    opt.push_back(&_CUSTOM_HardwareFinish);
    new Characteristic::Identify();
    new Characteristic::Manufacturer("hetrodo");
    new Characteristic::Model("HTDLockZB");
    new Characteristic::Name(DEVICE_NAME);
    const esp_app_desc_t *app_desc = esp_app_get_description();
    std::string app_version = app_desc->version;
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_BT);
    char macStr[9] = {0};
    sprintf(macStr, "%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3]);
    std::string serialNumber = "HTD-";
    serialNumber.append(macStr);
    new Characteristic::SerialNumber(serialNumber.c_str());
    new Characteristic::FirmwareRevision(app_version.c_str());
    std::array<uint8_t, 6> decB64 = hk_color_vals[HK_COLOR::SILVER];
    TLV8 hwfinish(NULL, 0);
    hwfinish.unpack(decB64.data(), decB64.size());
    new Characteristic::HardwareFinish(hwfinish);

  } // end constructor
};

struct LockMechanism final : Service::LockMechanism
{
  const char *TAG = "LockMechanism";

  LockMechanism() : Service::LockMechanism()
  {
    LOG(I, "Configuring LockMechanism");
    lockCurrentState = new Characteristic::LockCurrentState(1, true);
    lockTargetState = new Characteristic::LockTargetState(1, true);
    memcpy(ecpData + 8, readerData.reader_gid.data(), readerData.reader_gid.size());
    with_crc16(ecpData, 16, ecpData + 16);

    // int currentState = lockCurrentState->getNewVal();
    // Forward current state
  }

  boolean update()
  {
    int targetState = lockTargetState->getNewVal();
    LOG(I, "New LockState=%d, Current LockState=%d", targetState, lockCurrentState->getVal());

    // int currentState = lockCurrentState->getNewVal();
    // TODO: Handle the case where the current state is not LOCKED or UNLOCKED

    return (true);
  }
};

struct NFCAccess final : Service::NFCAccess
{
  SpanCharacteristic *configurationState;
  SpanCharacteristic *nfcControlPoint;
  SpanCharacteristic *nfcSupportedConfiguration;
  const char *TAG = "NFCAccess";

  NFCAccess() : Service::NFCAccess()
  {
    LOG(I, "Configuring NFCAccess");
    configurationState = new Characteristic::ConfigurationState();
    nfcControlPoint = new Characteristic::NFCAccessControlPoint();
    TLV8 conf(NULL, 0);
    conf.add(0x01, 0x10);
    conf.add(0x02, 0x10);
    nfcSupportedConfiguration = new Characteristic::NFCAccessSupportedConfiguration(conf);
  }

  boolean update()
  {
    LOG(D, "PROVISIONED READER KEY: %s", red_log::bufToHexString(readerData.reader_pk.data(), readerData.reader_pk.size()).c_str());
    LOG(D, "READER GROUP IDENTIFIER: %s", red_log::bufToHexString(readerData.reader_gid.data(), readerData.reader_gid.size()).c_str());
    LOG(D, "READER UNIQUE IDENTIFIER: %s", red_log::bufToHexString(readerData.reader_id.data(), readerData.reader_id.size()).c_str());

    TLV8 ctrlData(nullptr, 0);
    nfcControlPoint->getNewTLV(ctrlData);
    std::vector<uint8_t> tlvData(ctrlData.pack_size());
    ctrlData.pack(tlvData.data());
    if (tlvData.size() == 0)
      return false;
    LOG(D, "Decoded data: %s", red_log::bufToHexString(tlvData.data(), tlvData.size()).c_str());
    LOG(D, "Decoded data length: %d", tlvData.size());
    HK_HomeKit hkCtx(readerData, write_json_key, tlvData);
    std::vector<uint8_t> result = hkCtx.processResult();
    if (readerData.reader_gid.size() > 0)
    {
      memcpy(ecpData + 8, readerData.reader_gid.data(), readerData.reader_gid.size());
      with_crc16(ecpData, 16, ecpData + 16);
    }
    TLV8 res(nullptr, 0);
    res.unpack(result.data(), result.size());
    nfcControlPoint->setTLV(res, false);
    return true;
  }
};

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

void handle_door_cmd(const esp_zb_zcl_door_lock_cmd_id_t value) {
  const auto TAG = "handle_door_cmd";
  LOG(I, "Received door command: %d", value);

  if (value == ESP_ZB_ZCL_CMD_DOOR_LOCK_UNLOCK_DOOR) {
    digitalWrite(sigPin, LOW);
    vTaskDelay(250 / portTICK_PERIOD_MS);
    digitalWrite(sigPin, HIGH);
  }
}

void gnd_pulse_pin(const uint8_t pin, const TickType_t period = 250, const uint8_t times = 3) {
  for (uint8_t i = 0; i < times; i++) {
    digitalWrite(pin, LOW);
    vTaskDelay(period / portTICK_PERIOD_MS);
    digitalWrite(pin, HIGH);
    vTaskDelay(period / portTICK_PERIOD_MS);
  }
}

void try_unlock() {
  const auto TAG = "try_unlock";

  LOG(I, "Trying...");
  gnd_pulse_pin(GPIO_NUM_21, 500, 2);
  gnd_pulse_pin(GPIO_NUM_20, 2500, 1);
}

bool auth_raw_uid(const std::string &uid) {
  if (!acl.is_array()) {
    return false;
  }

  for (const auto& entry : acl) {
    if (entry.is_string() && entry.get<std::string>() == uid) {
      return true;
    }
  }

  return false;
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

nlohmann::json read_json_file(const char *path) {
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

bool write_json_key() {
  const auto TAG = "write_json_key";

  if (keys == nullptr && restart_task == nullptr) {
    xTaskCreate(restart_task_entry, "restart_task", 8192, nullptr, 1, &restart_task);
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

void delete_json_key()
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

std::vector<uint8_t> get_hash_identifier(const uint8_t *key, size_t len)
{
  auto TAG = "getHashIdentifier";
  LOG(V, "Key: %s, Length: %d", red_log::bufToHexString(key, len).c_str(), len);
  std::vector<unsigned char> hashable;
  std::string string = "key-identifier";
  hashable.insert(hashable.begin(), string.begin(), string.end());
  hashable.insert(hashable.end(), key, key + len);
  LOG(V, "Hashable: %s", red_log::bufToHexString(&hashable.front(), hashable.size()).c_str());
  uint8_t hash[32];
  mbedtls_sha256(&hashable.front(), hashable.size(), hash, 0);
  LOG(V, "HashIdentifier: %s", red_log::bufToHexString(hash, 8).c_str());
  return std::vector<uint8_t>{hash, hash + 8};
}

void pair_callback()
{
  LOG(I, "Pair callback!!!!!");

  if (HAPClient::nAdminControllers() == 0)
  {
    delete_json_key();
    return;
  }

  for (auto it = homeSpan.controllerListBegin(); it != homeSpan.controllerListEnd(); ++it)
  {
    std::vector<uint8_t> id = get_hash_identifier(it->getLTPK(), 32);
    LOG(D, "Found allocated controller - Hash: %s", red_log::bufToHexString(id.data(), 8).c_str());
    const hkIssuer_t *foundIssuer = nullptr;

    for (auto &&issuer : readerData.issuers)
    {
      if (std::equal(issuer.issuer_id.begin(), issuer.issuer_id.end(), id.begin()))
      {
        LOG(D, "Issuer %s already added, skipping", red_log::bufToHexString(issuer.issuer_id.data(), issuer.issuer_id.size()).c_str());
        foundIssuer = &issuer;
        break;
      }
    }

    if (foundIssuer == nullptr)
    {
      LOG(D, "Adding new issuer - ID: %s", red_log::bufToHexString(id.data(), 8).c_str());
      hkIssuer_t newIssuer;
      newIssuer.issuer_id = std::vector<uint8_t>{id.begin(), id.begin() + 8};
      newIssuer.issuer_pk.insert(newIssuer.issuer_pk.begin(), it->getLTPK(), it->getLTPK() + 32);
      readerData.issuers.emplace_back(newIssuer);
    }
  }

  write_json_key();
}

void status_callback(const HS_STATUS status) {
  static bool neededPairing = false;

  switch (status) {
    case HS_PAIRING_NEEDED:
      neededPairing = true;
      break;

    case HS_PAIRED:
      if (!neededPairing) {
        LOG(E, "Already paired, factory resetting...");
        homeSpan.processSerialCommand("F");
      }
      break;

    default:
      break;
  }
}

void nfc_retry_entry(void *arg)
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
  LOG(I, "Running...");

  if (uint32_t version_data = nfc->getFirmwareVersion(); !version_data)
  {
    LOG(E, "Error establishing PN532 connection");
    nfc->stop();
    xTaskCreate(nfc_retry_entry, "nfc_reconnect_task", 8192, nullptr, 1, &nfc_reconnect_task);
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
      xTaskCreate(nfc_retry_entry, "nfc_reconnect_task", 8192, nullptr, 1, &nfc_reconnect_task);
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
          try_unlock();

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
          try_unlock();
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
      const int startTime = millis();

      while (digitalRead(BOOT_PIN) == LOW) {
        delay(50);
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

void setup_homespan_task_entry(void *arg) {
  const auto TAG = "setup_homespan_task_entry";
  LOG(I, "Running...");

  //Begin HomeSpan Config
  const esp_app_desc_t *app_desc = esp_app_get_description();
  const std::string app_version = app_desc->version;

  homeSpan.setStatusAutoOff(15);
  homeSpan.setLogLevel(0);
  homeSpan.setSketchVersion(app_version.c_str());

  homeSpan.enableAutoStartAP();
  // homeSpan.enableOTA(/* ota password */);
  homeSpan.setPortNum(1201);
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_BT);
  char macStr[9] = {0};
  sprintf(macStr, "%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3]);
  homeSpan.setHostNameSuffix(macStr);
  homeSpan.begin(Category::Locks, "HTDLock", "HTD-", "HTDLockZB");

  new SpanAccessory();
  new NFCAccessoryInformation();
  new Service::HAPProtocolInformation();
  new Characteristic::Version();
  new LockManagement();
  new LockMechanism();
  new NFCAccess();

  homeSpan.setControllerCallback(pair_callback);
  homeSpan.setStatusCallback(status_callback);

  while (true) {
    homeSpan.poll();
    vTaskDelay(5 / portTICK_PERIOD_MS);
  }
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

    xTaskCreate(nfc_thread_entry, "nfc_task", 8192, nullptr, 1, &nfc_poll_task);

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

    xTaskCreate(hardware_task_entry, "hardware_task", 8192, nullptr, 1, &hardware_task);
  } else {
    LOG(E, "Key json not found, going HomeSpan route...");
    xTaskCreate(setup_homespan_task_entry, "setup_homespan_task", 8192, nullptr, 1, &setup_homespan_task);
  }
}

void loop() {}
