
#ifdef USE_EMULATION_L2H

#define XDRV_29 29

#include <stdint.h>
using namespace std;

//#define LOG(lvl, ...) Serial.printf(__VA_ARGS__)
#define LOG(lvl, ...) AddLog_P2(lvl, "L2H:" __VA_ARGS__)


extern "C"
{
  #include "l2h.h"
  
  void L2H_fill_ip(uint8_t *buf);
  void L2H_fill_mac(uint8_t *buf);
  uint32_t L2H_ssl_read(uint8_t *buf, uint32_t length);
  uint32_t L2H_ssl_write(uint8_t *buf, uint32_t length);
  uint32_t L2H_udp_write(uint8_t *ip, uint8_t *buf, uint32_t length);
  uint32_t L2H_udp_read(uint8_t *ip, uint8_t *buf, uint32_t length);
  uint32_t L2H_bcast_write(uint8_t *buf, uint32_t length);
  void L2H_cmd_callout(uint32_t cmd, uint8_t *buf, uint32_t length);

  static l2h_net_t L2H_net;
  static l2h_net_t *net = &L2H_net;
  static bool l2h_connected = false;

  /* yeah, including C code here might not be the most beautiful way, but it keeps the C code more generic */
  #include "l2h.inc"
}

WiFiClientSecure l2h_client;
WiFiUDP l2h_udp;
int l2h_lastConnect = 0;
int l2h_lastPkt = 0;

void L2H_connect()
{
  if (WiFi.status() != WL_CONNECTED)
  {
    return;
  }
  if (l2h_connected)
  {
    return;
  }

  l2h_udp.begin(35932);

  int curTime = millis();
  if (curTime - l2h_lastConnect < 5000)
  {
    return;
  }

  l2h_lastConnect = curTime;

  int8_t ret = 0;

  l2h_client.setInsecure();
  /* no memory on this device. packets will be small, so save mem here */
  l2h_client.setBufferSizes(512, 512);
  /* normally the devices connect to a load balancer which tells us to connect to this one. shortcut. directly connect. */
  l2h_client.connect("18.196.23.12", 33473);

  if (!l2h_client.connected())
  {
    LOG(LOG_LEVEL_ERROR, "L2H: Failed. Retrying connection");
  }
  else
  {
    l2h_send_login(net);
    l2h_send_idle(net);
    LOG(LOG_LEVEL_INFO, "L2H: Connected!");
    l2h_connected = true;
  }
}

void L2H_loop()
{
  int curTime = millis();

  L2H_connect();

  if (!l2h_connected)
  {
    return;
  }

  if (l2h_udp.parsePacket())
  {
    l2h_hdr_t *pkt = NULL;

    net->type = L2H_NET_UDP;
    pkt = l2h_read(net);
    if(pkt)
    {
      l2h_handle(net, pkt);
      l2h_packet_free(pkt);
    }
  }

  if (l2h_client.available())
  {
    l2h_hdr_t *pkt = NULL;

    net->type = L2H_NET_SSL;
    pkt = l2h_read(net);
    if(pkt)
    {
      l2h_handle(net, pkt);
      l2h_packet_free(pkt);
      l2h_lastPkt = curTime;
    }
  }

  if (curTime - l2h_lastPkt > 15000)
  {
    l2h_lastPkt = curTime;

    l2h_send_idle(net);
  }
}

void L2H_setup()
{
}

extern "C"
{
  void L2H_cmd_callout(uint32_t cmd, uint8_t *buf, uint32_t length)
  {
    switch (cmd)
    {
      case L2H_CMD_SWITCH:
        LOG(LOG_LEVEL_DEBUG, "Switch state: %d", buf[1]);
        ExecuteCommandPower(0, buf[1] != 0, SRC_L2H);
        break;

      case L2H_CMD_LAMPMODE:
        if (*buf < 5)
        {
          const char *modes[] = {"Sensor", "On", "Off", "Timed", "Random"};
          LOG(LOG_LEVEL_DEBUG, "Mode: %s", modes[*buf]);
          ExecuteCommandPower(0, (*buf =! 2), SRC_L2H);
        }
        break;

      case L2H_CMD_SENSMODE:
        LOG(LOG_LEVEL_DEBUG, "Sensormode: %d", *buf);
        break;

      case L2H_CMD_LUMDUR:
        LOG(LOG_LEVEL_DEBUG, "Lumen duration: %2.1f h", *buf * 0.5);
        break;

      case L2H_CMD_COUNTDOWN:
        LOG(LOG_LEVEL_DEBUG, "Countdown till: %02d:%02d:%02d (0x%02X)", buf[5], buf[6] , buf[7], buf[4]);
        break;

      case L2H_CMD_SCHED:
      {
        LOG(LOG_LEVEL_DEBUG, "Schedule:");
        uint32_t pos = 2;

        while(pos < length)
        {
          const char *days[] = { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };

          LOG(LOG_LEVEL_DEBUG, "  #%d", buf[pos]);
          LOG(LOG_LEVEL_DEBUG, "     Status: %s", buf[pos+1] ? "Enabled" : "Disabled");
          LOG(LOG_LEVEL_DEBUG, "     Type  : %s", (buf[pos+3] & 0x01) ? "Once" : "Daily");
          LOG(LOG_LEVEL_DEBUG, "     Days  : ");

          for(uint32_t day = 0; day < 7; day++)
          {
            if(buf[pos+3] & (0x80 >> day))
            {
              LOG(LOG_LEVEL_DEBUG, "             %s ", days[day]);
            }
          }
          LOG(LOG_LEVEL_DEBUG, "     On    : %02d:%02d", buf[pos+5], buf[pos+6]);
          LOG(LOG_LEVEL_DEBUG, "     Off   : %02d:%02d", buf[pos+10], buf[pos+11]);
          pos += 12;
        }
        break;
      }

      case L2H_CMD_ONDUR:
        LOG(LOG_LEVEL_DEBUG, "On duration: %d", buf[1] | ((uint16_t)buf[0] << 8));
        break;

      case L2H_CMD_LUX:
        LOG(LOG_LEVEL_DEBUG, "Lux: %d", buf[1] | ((uint16_t)buf[0] << 8));
        break;

      case L2H_CMD_COLRGB:
        LOG(LOG_LEVEL_DEBUG, "Color: %d, %d, %d", buf[0], buf[1], buf[2]);
        break;

      case L2H_CMD_COLWHITE:
        LOG(LOG_LEVEL_DEBUG, "White: %d", buf[0]);
        break;

      case L2H_CMD_MAXBR:
        LOG(LOG_LEVEL_DEBUG, "Brightness: %d", *buf);
        break;

      case L2H_CMD_LUMEN:
        LOG(LOG_LEVEL_DEBUG, "Lumen: %d", *buf);
        break;

      case L2H_CMD_FWUP:
        LOG(LOG_LEVEL_DEBUG, "Firmware: '%s'", buf);
        break;
    }
  }

  void L2H_fill_ip(uint8_t *buf)
  {
    IPAddress ip = WiFi.localIP();

    buf[0] = ip[0];
    buf[1] = ip[1];
    buf[2] = ip[2];
    buf[3] = ip[3];
  }

  void L2H_fill_mac(uint8_t *buf)
  {
    WiFi.macAddress(buf);
  }

  uint32_t L2H_ssl_read(uint8_t *buf, uint32_t length)
  {
    uint32_t ret = l2h_client.read(buf, length);
    return ret;
  }
  uint32_t L2H_ssl_write(uint8_t *buf, uint32_t length)
  {
    uint32_t ret = l2h_client.write(buf, length);
    return ret;
  }
  uint32_t L2H_udp_write(uint8_t *ip, uint8_t *buf, uint32_t length)
  {
    IPAddress dst_ip;

    dst_ip[0] = ip[0];
    dst_ip[1] = ip[1];
    dst_ip[2] = ip[2];
    dst_ip[3] = ip[3];

    l2h_udp.beginPacket(dst_ip, 35932);
    l2h_udp.write(buf, length);
    l2h_udp.endPacket();
    return length;
  }
  uint32_t L2H_udp_read(uint8_t *ip, uint8_t *buf, uint32_t length)
  {
    memcpy(ip, l2h_udp.remoteIP(), 4);
    return l2h_udp.read(buf, length);
  }
  uint32_t L2H_bcast_write(uint8_t *buf, uint32_t length)
  {
    IPAddress ip = WiFi.localIP();
    ip[3] = 255;

    l2h_udp.beginPacket(ip, 35932);
    l2h_udp.write(buf, length);
    l2h_udp.endPacket();

    return length;
  }
}

bool Xdrv29(uint8_t function)
{
  bool result = false;

  if ((EMUL_L2H == Settings.flag2.emulation)) {
    switch (function)
    {
      case FUNC_EVERY_100_MSECOND:
        L2H_loop();
        break;
      case FUNC_SET_DEVICE_POWER:
        l2h_lastPkt = 0;
        L2H_loop();
        break;
    }
  }
  return result;
}

#endif
