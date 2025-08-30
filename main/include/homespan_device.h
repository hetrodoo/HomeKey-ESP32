//
// Created by hetro on 25/08/2025.
//

#ifndef HOMEKEY_ESP32_HOMESPAN_DEVICE_H
#define HOMEKEY_ESP32_HOMESPAN_DEVICE_H
#include "HomeSpan.h"
#include "logging.h"
#include "tasker.h"
#include "keys.h"

inline SpanCharacteristic *lockCurrentState;
inline SpanCharacteristic *lockTargetState;
inline uint8_t ecpData[18] = {0x6A, 0x2, 0xCB, 0x2, 0x6, 0x2, 0x11, 0x0};
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
    std::array<uint8_t, 6> decB64 = hk_color_vals[HK_COLOR::BLACK];
    TLV8 hwfinish(nullptr, 0);
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

inline std::vector<uint8_t> get_hash_identifier(const uint8_t *key, size_t len)
{
  const auto TAG = "get_hash_identifier";

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

inline void pair_callback()
{
  const auto TAG = "pair_callback";

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

inline void status_callback(const HS_STATUS status) {
  const auto TAG = "status_callback";

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

inline void setup_homespan() {
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
}

#endif //HOMEKEY_ESP32_HOMESPAN_DEVICE_H