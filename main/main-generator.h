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
#include "HomeSpan.h"
#include "chrono"
#include "HK_HomeKit.h"
#include "helper.h"
#include "esp_app_desc.h"
#include "pins_arduino.h"
#include "NFC_SERV_CHARS.h"
#include <mbedtls/sha256.h>
#include <esp_mac.h>

const char *TAG = "MAIN";

nvs_handle savedData;
readerData_t readerData;
uint8_t ecpData[18] = {0x6A, 0x2, 0xCB, 0x2, 0x6, 0x2, 0x11, 0x0};
const std::array<std::array<uint8_t, 6>, 4> hk_color_vals = {{{0x01, 0x04, 0xce, 0xd5, 0xda, 0x00}, {0x01, 0x04, 0xaa, 0xd6, 0xec, 0x00}, {0x01, 0x04, 0xe3, 0xe3, 0xe3, 0x00}, {0x01, 0x04, 0x00, 0x00, 0x00, 0x00}}};

KeyFlow hkFlow = KeyFlow::kFlowFAST;
bool hkAltActionActive = false;
SpanCharacteristic *lockCurrentState;
SpanCharacteristic *lockTargetState;

std::string platform_create_id_string(void)
{
  uint8_t mac[6];
  char id_string[13];
  esp_read_mac(mac, ESP_MAC_BT);
  sprintf(id_string, "ESP32_%02x%02X%02X", mac[3], mac[4], mac[5]);
  return std::string(id_string);
}

bool save_to_nvs()
{
  std::vector<uint8_t> serialized = nlohmann::json::to_msgpack(readerData);
  esp_err_t set_nvs = nvs_set_blob(savedData, "READERDATA", serialized.data(), serialized.size());
  esp_err_t commit_nvs = nvs_commit(savedData);
  LOG(D, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
  LOG(D, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
  return !set_nvs && !commit_nvs;
}

struct LockManagement : Service::LockManagement
{
  SpanCharacteristic *lockControlPoint;
  SpanCharacteristic *version;
  const char *TAG = "LockManagement";

  LockManagement() : Service::LockManagement()
  {

    LOG(I, "Configuring LockManagement"); // initialization message

    lockControlPoint = new Characteristic::LockControlPoint();
    version = new Characteristic::Version();

  } // end constructor

}; // end LockManagement

struct NFCAccessoryInformation : Service::AccessoryInformation
{
  const char *TAG = "NFCAccessoryInformation";

  NFCAccessoryInformation() : Service::AccessoryInformation()
  {

    LOG(I, "Configuring NFCAccessoryInformation"); // initialization message

    opt.push_back(&_CUSTOM_HardwareFinish);
    new Characteristic::Identify();
    new Characteristic::Manufacturer("rednblkx");
    new Characteristic::Model("HomeKey-ESP32");
    new Characteristic::Name(DEVICE_NAME);
    const esp_app_desc_t *app_desc = esp_app_get_description();
    std::string app_version = app_desc->version;
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_BT);
    char macStr[9] = {0};
    sprintf(macStr, "%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3]);
    std::string serialNumber = "HK-";
    serialNumber.append(macStr);
    new Characteristic::SerialNumber(serialNumber.c_str());
    new Characteristic::FirmwareRevision(app_version.c_str());
    std::array<uint8_t, 6> decB64 = hk_color_vals[HK_COLOR::SILVER];
    TLV8 hwfinish(NULL, 0);
    hwfinish.unpack(decB64.data(), decB64.size());
    new Characteristic::HardwareFinish(hwfinish);

  } // end constructor
};

struct LockMechanism : Service::LockMechanism
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

struct NFCAccess : Service::NFCAccess
{
  SpanCharacteristic *configurationState;
  SpanCharacteristic *nfcControlPoint;
  SpanCharacteristic *nfcSupportedConfiguration;
  const char *TAG = "NFCAccess";

  NFCAccess() : Service::NFCAccess()
  {
    LOG(I, "Configuring NFCAccess"); // initialization message
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

    TLV8 ctrlData(NULL, 0);
    nfcControlPoint->getNewTLV(ctrlData);
    std::vector<uint8_t> tlvData(ctrlData.pack_size());
    ctrlData.pack(tlvData.data());
    if (tlvData.size() == 0)
      return false;
    LOG(D, "Decoded data: %s", red_log::bufToHexString(tlvData.data(), tlvData.size()).c_str());
    LOG(D, "Decoded data length: %d", tlvData.size());
    HK_HomeKit hkCtx(readerData, savedData, "READERDATA", tlvData);
    std::vector<uint8_t> result = hkCtx.processResult();
    if (readerData.reader_gid.size() > 0)
    {
      memcpy(ecpData + 8, readerData.reader_gid.data(), readerData.reader_gid.size());
      with_crc16(ecpData, 16, ecpData + 16);
    }
    TLV8 res(NULL, 0);
    res.unpack(result.data(), result.size());
    nfcControlPoint->setTLV(res, false);
    return true;
  }
};

std::vector<uint8_t> getHashIdentifier(const uint8_t *key, size_t len)
{
  const char *TAG = "getHashIdentifier";
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

void deleteReaderData(const char *buf = "")
{
  esp_err_t erase_nvs = nvs_erase_key(savedData, "READERDATA");
  esp_err_t commit_nvs = nvs_commit(savedData);
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

void setLogLevel(const char *buf)
{
  esp_log_level_t level = esp_log_level_get("*");
  if (strncmp(buf + 1, "E", 1) == 0)
  {
    level = ESP_LOG_ERROR;
    LOG(I, "ERROR");
  }
  else if (strncmp(buf + 1, "W", 1) == 0)
  {
    level = ESP_LOG_WARN;
    LOG(I, "WARNING");
  }
  else if (strncmp(buf + 1, "I", 1) == 0)
  {
    level = ESP_LOG_INFO;
    LOG(I, "INFO");
  }
  else if (strncmp(buf + 1, "D", 1) == 0)
  {
    level = ESP_LOG_DEBUG;
    LOG(I, "DEBUG");
  }
  else if (strncmp(buf + 1, "V", 1) == 0)
  {
    level = ESP_LOG_VERBOSE;
    LOG(I, "VERBOSE");
  }
  else if (strncmp(buf + 1, "N", 1) == 0)
  {
    level = ESP_LOG_NONE;
    LOG(I, "NONE");
  }

  esp_log_level_set(TAG, level);
  esp_log_level_set("HK_HomeKit", level);
  esp_log_level_set("HKAuthCtx", level);
  esp_log_level_set("HKFastAuth", level);
  esp_log_level_set("HKStdAuth", level);
  esp_log_level_set("HKAttestAuth", level);
  esp_log_level_set("PN532", level);
  esp_log_level_set("PN532_SPI", level);
  esp_log_level_set("ISO18013_SC", level);
  esp_log_level_set("LockMechanism", level);
  esp_log_level_set("NFCAccess", level);
  esp_log_level_set("actions-config", level);
  esp_log_level_set("misc-config", level);
}

void setFlow(const char *buf)
{
  switch (buf[1])
  {
  case '0':
    hkFlow = KeyFlow::kFlowFAST;
    LOG(I, "FAST Flow");
    break;

  case '1':
    hkFlow = KeyFlow::kFlowSTANDARD;
    LOG(I, "STANDARD Flow");
    break;
  case '2':
    hkFlow = KeyFlow::kFlowATTESTATION;
    LOG(I, "ATTESTATION Flow");
    break;

  default:
    LOG(I, "0 = FAST flow, 1 = STANDARD Flow, 2 = ATTESTATION Flow");
    break;
  }
}

void print_issuers(const char *buf)
{
  for (auto &&issuer : readerData.issuers)
  {
    LOG(I, "Issuer ID: %s, Public Key: %s", red_log::bufToHexString(issuer.issuer_id.data(), issuer.issuer_id.size()).c_str(), red_log::bufToHexString(issuer.issuer_pk.data(), issuer.issuer_pk.size()).c_str());
    for (auto &&endpoint : issuer.endpoints)
    {
      LOG(I, "Endpoint ID: %s, Public Key: %s", red_log::bufToHexString(endpoint.endpoint_id.data(), endpoint.endpoint_id.size()).c_str(), red_log::bufToHexString(endpoint.endpoint_pk.data(), endpoint.endpoint_pk.size()).c_str());
    }
  }
}

void pairCallback()
{
  if (HAPClient::nAdminControllers() == 0)
  {
    deleteReaderData(NULL);
    return;
  }
  for (auto it = homeSpan.controllerListBegin(); it != homeSpan.controllerListEnd(); ++it)
  {
    std::vector<uint8_t> id = getHashIdentifier(it->getLTPK(), 32);
    LOG(D, "Found allocated controller - Hash: %s", red_log::bufToHexString(id.data(), 8).c_str());
    hkIssuer_t *foundIssuer = nullptr;
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
  save_to_nvs();
}

void wifiCallback(int status)
{
  if (status == 1)
  {
    // Successfully connected to WiFi
  }
}

void setup()
{
  Serial.begin(115200);
  const esp_app_desc_t *app_desc = esp_app_get_description();
  std::string app_version = app_desc->version;

  size_t len;
  const char *TAG = "SETUP";

  nvs_open("SAVED_DATA", NVS_READWRITE, &savedData);

  if (!nvs_get_blob(savedData, "READERDATA", NULL, &len))
  {
    std::vector<uint8_t> savedBuf(len);
    nvs_get_blob(savedData, "READERDATA", savedBuf.data(), &len);
    LOG(D, "NVS READERDATA LENGTH: %d", len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, savedBuf.data(), savedBuf.size(), ESP_LOG_VERBOSE);
    nlohmann::json data = nlohmann::json::from_msgpack(savedBuf);
    if (!data.is_discarded())
    {
      data.get_to<readerData_t>(readerData);
      LOG(I, "Reader Data loaded from NVS");
      LOG(I, "Json: %s", data.dump().c_str());
    }
  }

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
  homeSpan.begin(Category::Locks, "HomeKeyEsp32", "HK-", "HomeKey-ESP32");

  new SpanUserCommand('D', "Delete Home Key Data", deleteReaderData);
  new SpanUserCommand('L', "Set Log Level", setLogLevel);
  new SpanUserCommand('F', "Set HomeKey Flow", setFlow);
  new SpanUserCommand('P', "Print Issuers", print_issuers);
  new SpanUserCommand('R', "Remove Endpoints", [](const char *)
                      {
    for (auto&& issuer : readerData.issuers) {
      issuer.endpoints.clear();
    }
    save_to_nvs(); });

  new SpanAccessory();
  new NFCAccessoryInformation();
  new Service::HAPProtocolInformation();
  new Characteristic::Version();
  new LockManagement();
  new LockMechanism();
  new NFCAccess();

  homeSpan.setControllerCallback(pairCallback);
  homeSpan.setConnectionCallback(wifiCallback);
}

void loop()
{
  homeSpan.poll();
  vTaskDelay(5);
}
