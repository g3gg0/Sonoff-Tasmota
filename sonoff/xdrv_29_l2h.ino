/*
  xdrv_29_l2h.ino - Link2Home emulator - Arduino upper layer

  Copyright (C) 2019  Georg Hofstetter

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifdef USE_EMULATION_L2H

#define XDRV_29 29

#include <stdint.h>
using namespace std;

#define LOG(lvl, ...) AddLog_P2(lvl, "L2H: " __VA_ARGS__)


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
int l2h_lastPktReceived = 0;

bool L2H_countdownEnabled = false;
int L2H_countdownHours = 0;
int L2H_countdownMinutes = 0;
int L2H_countdownSeconds = 0;

void L2H_disconnect()
{
  l2h_client.stop();
  l2h_udp.stop();
  l2h_connected = false;
}

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
  /* not a lot memory on this device. packets will be small, so save mem herewith */
  l2h_client.setBufferSizes(512, 512);
  /* normally the devices connect to a load balancer which tells us to connect to this one. shortcut here directly connect. */
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
      l2h_lastPktReceived = curTime;
    }
  }

  if (curTime - l2h_lastPkt > 15000)
  {
    l2h_lastPkt = curTime;

    l2h_send_idle(net);
  }

  if (curTime - l2h_lastPktReceived > 30000)
  {
    LOG(LOG_LEVEL_ERROR, "Timeout, nothing received for 30 seconds.");
    L2H_disconnect();
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
          ExecuteCommandPower(0, (*buf == L2H_MODE_ON), SRC_L2H);
        }
        break;

      case L2H_CMD_SENSMODE:
        LOG(LOG_LEVEL_DEBUG, "Sensormode: %d", *buf);
        break;

      case L2H_CMD_LUMDUR:
        LOG(LOG_LEVEL_DEBUG, "Auto duration: %2.1f h", *buf * 0.5f);
        break;

      case L2H_CMD_COUNTDOWN:

        if(RtcTime.valid)
        {
          /* what about time zones? */
          ExecuteCommandPower(0, 1, SRC_L2H);
          L2H_countdownHours = buf[5];
          L2H_countdownMinutes = buf[6];
          L2H_countdownSeconds = buf[7];
          L2H_countdownEnabled = true;

          LOG(LOG_LEVEL_DEBUG, "Countdown till: %02d:%02d:%02d (now is %02d:%02d:%02d)", L2H_countdownHours, L2H_countdownMinutes, L2H_countdownSeconds, RtcTime.hour, RtcTime.minute, RtcTime.second);
        }
        else
        {
          LOG(LOG_LEVEL_ERROR, "No RTC time available, not setting countdown");
        }
        
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
      {
        char command[32];
        LOG(LOG_LEVEL_DEBUG, "Color: %d, %d, %d", buf[0], buf[1], buf[2]);
        snprintf_P(command, sizeof(command), PSTR(D_CMND_COLOR " %02X%02x%02x"), buf[0], buf[1], buf[2]);
        ExecuteCommand(command, SRC_L2H);
        break;
      }

      case L2H_CMD_COLWHITE:
        LOG(LOG_LEVEL_DEBUG, "White: %d", buf[0]);
        break;

      case L2H_CMD_MAXBR:
      {
        char command[32];
        uint32_t brightness = (*buf * 100) / 202;
        LOG(LOG_LEVEL_DEBUG, "Brightness: raw %d -> %d scaled", *buf, brightness);
        
        snprintf_P(command, sizeof(command), PSTR(D_CMND_DIMMER " %d"), brightness);
        ExecuteCommand(command, SRC_L2H);
        break;
      }

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

void L2H_checkCountdown()
{
  if (RtcTime.valid && L2H_countdownEnabled)
  {
    if (L2H_countdownHours == RtcTime.hour && 
        L2H_countdownMinutes == RtcTime.minute &&
        L2H_countdownSeconds == RtcTime.second)
    {
      LOG(LOG_LEVEL_DEBUG, "Countdown time reached, switch off.");
      ExecuteCommandPower(0, 0, SRC_L2H);
      L2H_countdownEnabled = false;
    }
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
        L2H_checkCountdown();
        break;
      case FUNC_SET_DEVICE_POWER:
        l2h_send_idle(net);
        break;
    }
  }
  return result;
}

#endif
