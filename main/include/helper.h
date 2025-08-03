enum HK_COLOR
{
  TAN,
  GOLD,
  SILVER,
  BLACK
};

#define DEVICE_NAME "HK" //Device name

void crc16a(unsigned char *data, unsigned int size, unsigned char *result)
{
  unsigned short w_crc = 0x6363;

  for (unsigned int i = 0; i < size; ++i)
  {
    unsigned char byte = data[i];
    byte = (byte ^ (w_crc & 0x00FF));
    byte = ((byte ^ (byte << 4)) & 0xFF);
    w_crc = ((w_crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 0xFFFF;
  }

  result[0] = static_cast<unsigned char>(w_crc & 0xFF);
  result[1] = static_cast<unsigned char>((w_crc >> 8) & 0xFF);
}

void with_crc16(unsigned char *data, unsigned int size, unsigned char *result)
{
  crc16a(data, size, result);
}
