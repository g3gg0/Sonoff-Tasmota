/*
  l2h.inc - Link2Home emulator - C implementation

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

  DISCLAIMER:
 -------------
  This protocol was reverse engineered by just analyzing the communication
  between the server and the smart wall plug.
  As the device did not verify the certificate, it was an easy to set up a
  MITM scenario which did not require to crack anything open.
  So nothing shady happened during the reverse engineering process.

  Using their services should also be legal as we do not fake anything and 
  are always honest when reporting our MAC address.
  So there is no fraud happening and no security mechanisms are overridden.
  They could easily lock out non-Link2Home devices by blocking foreign MACs.

  As soon this happens, users would have to deliberately fake MAC addresses
  which could be interpreted as an attack against their system.

  IMPORTANT:
 -------------
  In any case, please do not use this code or this knowledge derieved from
  it to attack the servers or devices of other Link2Home users.
  It is clear that there is no real security at all.

  Their service, open like a public park. So behave and be kind to others.

*/
#include <stdint.h>


uint8_t l2h_verbose = 0;
uint8_t l2h_mac[6];
uint8_t l2h_companyCode = 0x02;
uint8_t l2h_deviceType = L2H_DEVICE_GARDENLAMP;
uint16_t l2h_authCode = 29008;
uint16_t l2h_sequence = 0;
uint32_t l2h_expected_mode = 0;

void l2h_send_status(l2h_net_t *net);
void l2h_send_idle(l2h_net_t *net);
void l2h_send_login(l2h_net_t *net);

/* ******************************************************* */
/*           PA - platform adaption area                   */
/* ******************************************************* */

//#define l2h_pa_printf(...)
#define l2h_pa_printf Serial.printf

uint32_t pa_time()
{
    return millis();
}

void pa_cmd_callout(uint32_t cmd, uint8_t *buf, uint32_t length)
{
    L2H_cmd_callout(cmd, buf, length);
}

uint32_t pa_ssl_read(l2h_net_t *net, uint8_t *buf, uint32_t length)
{
    return L2H_ssl_read(buf, length);
}

uint32_t pa_ssl_write(l2h_net_t *net, uint8_t *buf, uint32_t length)
{
    return L2H_ssl_write(buf, length);
}

uint32_t pa_udp_write(l2h_net_t *net, uint8_t *buf, uint32_t length)
{
    return L2H_udp_write(net->ip, buf, length);
}

uint32_t pa_udp_read(l2h_net_t *net, uint8_t *buf, uint32_t length)
{
    return L2H_udp_read(net->ip, buf, length);
}

uint32_t pa_bcast_write(l2h_net_t *net, uint8_t *buf, uint32_t length)
{
    return L2H_bcast_write(buf, length);
}

/* ******************************************************* */
/*         L2H - probably needs modification               */
/* ******************************************************* */

void l2h_packet_free(l2h_hdr_t *pkt)
{
    free(pkt);
}

l2h_hdr_t *l2h_packet_alloc(uint16_t len)
{
    uint8_t *pkt_buf = (uint8_t *)malloc(sizeof(l2h_hdr_t) + len + 32);
    l2h_hdr_t *pkt = (l2h_hdr_t *)pkt_buf;

    if (pkt_buf == NULL)
    {
        return NULL;
    }

    pkt->hdr = L2H_PKT_HDR;
    L2H_fill_mac(l2h_mac);
    memcpy(pkt->mac, l2h_mac, 6);
    pkt->length = 6 + len;
    pkt->companyCode = l2h_companyCode;
    pkt->deviceType = l2h_deviceType;
    pkt->authCode = l2h_authCode;

    return pkt;
}

void l2h_dump_hex(uint8_t *buffer, int length)
{
    for (int pos = 0; pos < length; pos++)
    {
        l2h_pa_printf("%02X ", buffer[pos]);
    }
    l2h_pa_printf("\n");
}

void l2h_dump_pkt(l2h_hdr_t *pkt, const char *msg)
{
    l2h_pa_printf("%s\n", msg);
    l2h_pa_printf(" Header: 0x%02X\n", pkt->hdr);
    l2h_pa_printf(" Type:   0x%02X\n", pkt->type);
    l2h_pa_printf(" MAC:    %02X:%02X:%02X:%02X:%02X:%02X\n", pkt->mac[0], pkt->mac[1], pkt->mac[2], pkt->mac[3], pkt->mac[4], pkt->mac[5]);
    l2h_pa_printf(" Length: 0x%04X\n", (pkt->length));
    l2h_pa_printf(" Seq:    0x%04X\n", (pkt->sequence));
    l2h_pa_printf(" Comp:   0x%02X\n", pkt->companyCode);
    l2h_pa_printf(" Device: 0x%02X\n", pkt->deviceType);
    l2h_pa_printf(" Auth:   0x%04X\n", (pkt->authCode));
    l2h_pa_printf(" Data:   ");
    l2h_dump_hex(l2h_get_payload(pkt), (pkt->length) - 6);
    l2h_pa_printf("\n");
}

/* ******************************************************* */
/*         L2H - most likely not needed to modify          */
/* ******************************************************* */

/* get area which contains the packets payload */
uint8_t *l2h_get_payload(l2h_hdr_t *pkt)
{
    return &((uint8_t *)pkt)[sizeof(l2h_hdr_t)];
}

/* the fist payload byte is the command */
uint8_t l2h_get_cmd(l2h_hdr_t *pkt)
{
    return *l2h_get_payload(pkt);
}

/* data for the given command */
uint8_t *l2h_get_data(l2h_hdr_t *pkt)
{
    return &l2h_get_payload(pkt)[1];
}

l2h_hdr_t *l2h_read(l2h_net_t *net)
{
    l2h_hdr_t *pkt = l2h_packet_alloc(L2H_MAX_PKT_LEN);
    uint8_t *read_buf = (uint8_t *)pkt;
    int ret = 0;

    switch (net->type)
    {
        case L2H_NET_SSL:
        {
            ret = pa_ssl_read(net, read_buf, 16);
            break;
        }

        case L2H_NET_UDP:
        {
            ret = pa_udp_read(net, read_buf, L2H_MAX_PKT_LEN);
            break;
        }
    }

    if (ret < 16 || ntohs(pkt->length) > (L2H_MAX_PKT_LEN - 16))
    {
        l2h_packet_free(pkt);
        return NULL;
    }

    if (l2h_verbose)
    {
        l2h_dump_pkt(pkt, (char *)"Received:");
    }

    pkt->length = ntohs(pkt->length);
    pkt->sequence = ntohs(pkt->sequence);
    pkt->authCode = htonl(pkt->authCode);

    switch (net->type)
    {
        case L2H_NET_SSL:
        {
            ret += pa_ssl_read(net, &read_buf[16], pkt->length - 6);
            break;
        }

        case L2H_NET_UDP:
        {
            if (memcmp(&pkt->mac, l2h_mac, 6))
            {
                if (memcmp(&pkt->mac, "\xff\xff\xff\xff\xff\xff", 6))
                {
                    l2h_packet_free(pkt);
                    return NULL;
                }
            }
            break;
        }
    }

    if (ret != pkt->length + 10)
    {
        l2h_packet_free(pkt);
        return NULL;
    }

    return pkt;
}

l2h_hdr_t *l2h_packet_alloc_request(uint8_t command, uint8_t *payload, uint16_t payload_len)
{
    l2h_hdr_t *pkt = l2h_packet_alloc(1 + payload_len);
    uint8_t *data_buf = l2h_get_payload(pkt);

    pkt->type = L2H_PKT_REQUEST;
    pkt->sequence = l2h_sequence++;

    data_buf[0] = command;
    memcpy(&data_buf[1], payload, payload_len);

    return pkt;
}

l2h_hdr_t *l2h_packet_alloc_response(l2h_hdr_t *ref_pkt, uint8_t *payload, uint16_t payload_len)
{
    l2h_hdr_t *pkt = l2h_packet_alloc(1 + payload_len);
    uint8_t *data_buf = l2h_get_payload(pkt);

    pkt->type = ref_pkt->type | L2H_PKT_RESPONSE;
    pkt->sequence = ref_pkt->sequence;

    data_buf[0] = l2h_get_cmd(ref_pkt);
    memcpy(&data_buf[1], payload, payload_len);

    return pkt;
}

void l2h_write(l2h_net_t *net, l2h_hdr_t *pkt)
{
    uint32_t len = pkt->length + 10;

    pkt->length = htons(pkt->length);
    pkt->sequence = htons(pkt->sequence);
    pkt->authCode = htons(pkt->authCode);

    switch (net->type)
    {
        case L2H_NET_SSL:
        {
            pa_ssl_write(net, (uint8_t *)pkt, len);
            break;
        }

        case L2H_NET_UDP:
        {
            pa_udp_write(net, (uint8_t *)pkt, len);
            break;
        }

        case L2H_NET_BCAST:
        {
            pa_bcast_write(net, (uint8_t *)pkt, len);
            break;
        }
    }

    if (l2h_verbose)
    {
        l2h_dump_pkt(pkt, (char *)"Sent:");
    }
}

void l2h_send_response(l2h_net_t *net, l2h_hdr_t *ref_pkt, uint8_t *payload, uint16_t payload_len)
{
    l2h_hdr_t *resp = l2h_packet_alloc_response(ref_pkt, payload, payload_len);
    l2h_write(net, resp);
    l2h_packet_free(resp);
}

void l2h_send_request(l2h_net_t *net, uint8_t command, uint8_t *payload, uint16_t payload_len)
{
    l2h_hdr_t *resp = l2h_packet_alloc_request(command, payload, payload_len);
    l2h_write(net, resp);
    l2h_packet_free(resp);
}

void l2h_append_string(uint8_t *dst, uint32_t dst_size, const char *str, uint32_t *pos)
{
    uint32_t len = strlen(str);

    /* make sure there is enough room to append */
    if(dst_size < *pos + len + 1)
    {
        return;
    }
    /* store length byte */
    dst[*pos] = len;

    /* copy string */
    memcpy(&dst[*pos + 1], str, len);

    /* update current position */
    *pos += len + 1;
}

void l2h_handle(l2h_net_t *net, l2h_hdr_t *pkt)
{
    uint8_t cmd_id = l2h_get_cmd(pkt);
    uint8_t *cmd_data = l2h_get_data(pkt);
    uint16_t seq = pkt->sequence;
    uint8_t type = pkt->type;

    switch (type & 0x0F)
    {
        case 0x00:
            break;
        case 0x04:
            break;
        case 0x06:
            /* ignore responses */
            return;

        default:
            break;
    }

    switch (cmd_id)
    {
        case L2H_CMD_SWITCH:
        {
            l2h_pa_printf(" -> switch set 0x%02X\n", cmd_data[1]);

            pa_cmd_callout(cmd_id, cmd_data, 2);

            uint8_t data[2] = {0x01, 0xFF};
            data[0] = l2h_expected_mode;
            data[1] = power ? 0xFF : 0x00;

            l2h_send_response(net, pkt, data, 2);
            l2h_send_request(net, L2H_CMD_SWITCH_REPORT, data, 2);
            break;
        }

        case L2H_CMD_VERSION:
        {
            uint8_t buffer[32];
            uint32_t pos = 0;

            /* hardware/software versions */
            l2h_append_string(buffer, sizeof(buffer), L2H_VER_HW, &pos);
            l2h_append_string(buffer, sizeof(buffer), L2H_VER_SW, &pos);
            l2h_send_response(net, pkt, buffer, pos);

            /* timezone */
            pos = 0;
            l2h_append_string(buffer, sizeof(buffer), L2H_TZ, &pos);
            l2h_send_request(net, L2H_CMD_ZONEID, buffer, pos);

            /* city ID (see https://github.com/Shuang0420/aiml/blob/master/cn-examples/cities.csv) */
            pos = 0;
            l2h_append_string(buffer, sizeof(buffer), L2H_CITYID, &pos);
            l2h_send_request(net, L2H_CMD_CITYID, buffer, pos);

            break;
        }

        case L2H_CMD_SCHED:
        {
            pa_cmd_callout(cmd_id, cmd_data, pkt->length - 7);
            l2h_dump_pkt(pkt, "Schedule packet");
            l2h_send_response(net, pkt, (uint8_t *)"\x01", 1);
            break;
        }

        case L2H_CMD_COUNTDOWN:
        {
            static int length = 0;
            pa_cmd_callout(cmd_id, cmd_data, 8);
            l2h_dump_pkt(pkt, "Countdown packet");
            l2h_send_response(net, pkt, (uint8_t *)"\xFF", 1); /* not sure about the reply */
            break;
        }

        case L2H_CMD_STATUS_05:
        {
            l2h_pa_printf(" -> L2H_CMD_STATUS_05 set 0x%02X\n", cmd_data[1]);

            pa_cmd_callout(cmd_id, cmd_data, 3);

            uint8_t data[2] = {0x01, 0xFF};
            data[0] = l2h_expected_mode;
            data[1] = power ? 0xFF : 0x00;

            l2h_send_response(net, pkt, data, 2);
            break;
        }

        case L2H_CMD_ALLID:
        {
            uint8_t buffer[64];
            uint32_t pos = 0;

            buffer[0] = 0x00;
            buffer[1] = 0x3C; /* not sure about it */
            pos = 2;
            l2h_append_string(buffer, sizeof(buffer), L2H_TZ, &pos);
            l2h_append_string(buffer, sizeof(buffer), L2H_CITYID, &pos);
            l2h_append_string(buffer, sizeof(buffer), L2H_COORD, &pos);
            l2h_send_response(net, pkt, buffer, pos);
            break;
        }

        case L2H_CMD_UNK_12:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_UNK_12");
            l2h_send_response(net, pkt, (uint8_t *)"\x01\x01", 2);

            /* now is a good time to report our current state */
            l2h_send_idle(net);
            break;
        }

        case L2H_CMD_UNK_02:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_UNK_02");
            l2h_send_response(net, pkt, (uint8_t *)"\x01\x00", 2);
            break;
        }

        case L2H_CMD_UNK_08:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_UNK_08");
            l2h_send_response(net, pkt, (uint8_t *)"\x01\x00\x01\x00\x00\x00\x00\x00\x00", 9);
            break;
        }

        case L2H_CMD_UNK_0B:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_UNK_0B");
            l2h_send_response(net, pkt, (uint8_t *)"", 0);
            break;
        }

        case L2H_CMD_PAIR_24:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_PAIR_24");
            l2h_send_response(net, pkt, (uint8_t *)"", 0);
            break;
        }

        case L2H_CMD_UNPAIR_14:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_UNPAIR_14");
            l2h_send_response(net, pkt, (uint8_t *)"", 0);
            break;
        }

        case L2H_CMD_IDLE:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_IDLE");
            l2h_send_response(net, pkt, (uint8_t *)"\x00\x0a", 2);
            break;
        }

        case L2H_CMD_SET_ALLID:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_SET_ALLID");
            l2h_send_response(net, pkt, (uint8_t *)"", 0);
            break;
        }

        case L2H_CMD_ANNCOUNCE:
        {
            uint8_t bcast_data[10];

            L2H_fill_ip(&bcast_data[0]);
            memcpy(&bcast_data[4], l2h_mac, 6);

            l2h_send_response(net, pkt, bcast_data, 10);
            break;
        }

        case L2H_CMD_LAMPMODE:
        {
            l2h_expected_mode = *cmd_data;

            pa_cmd_callout(cmd_id, cmd_data, 1);
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_SENSMODE:
        {
            pa_cmd_callout(cmd_id, cmd_data, 1);
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_TEST:
        {
            l2h_send_response(net, pkt, (uint8_t *)"", 0);
            break;
        }

        case L2H_CMD_PANIC:
        {
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_LUMDUR:
        {
            pa_cmd_callout(cmd_id, cmd_data, 1);
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_LUMEN:
        {
            pa_cmd_callout(cmd_id, cmd_data, 1);
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_ONDUR:
        {
            pa_cmd_callout(cmd_id, cmd_data, 2);
            l2h_send_response(net, pkt, cmd_data, 2);
            break;
        }

        case L2H_CMD_LUX:
        {
            pa_cmd_callout(cmd_id, cmd_data, 2);
            l2h_send_response(net, pkt, cmd_data, 2);
            break;
        }

        case L2H_CMD_SENSLVL:
        {
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_COLRGB:
        {
            pa_cmd_callout(cmd_id, cmd_data, 3);
            l2h_send_response(net, pkt, cmd_data, 3);
            break;
        }

        case L2H_CMD_COLWHITE:
        {
            pa_cmd_callout(cmd_id, cmd_data, 1);
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_MAXBR:
        {
            pa_cmd_callout(cmd_id, cmd_data, 1);
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        case L2H_CMD_FWUP:
        {
            pa_cmd_callout(cmd_id, cmd_data, 1);
            break;
        }
        case L2H_CMD_UNK_5B:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_UNK_5B");
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }
        case L2H_CMD_UNK_56:
        {
            l2h_dump_pkt(pkt, "L2H_CMD_UNK_56");
            l2h_send_response(net, pkt, cmd_data, 1);
            break;
        }

        default:
            l2h_pa_printf(" ERROR: unknown request 0x%02X\n", cmd_id);
            break;
    }
}

void l2h_send_status(l2h_net_t *net)
{
    uint8_t data[2] = { 0x01, 0xFF };

    if(!power)
    {
        l2h_expected_mode = L2H_MODE_OFF;
    }
    else if(l2h_expected_mode == L2H_MODE_OFF)
    {
        l2h_expected_mode = L2H_MODE_ON;
    }

    if(l2h_deviceType != L2H_DEVICE_GARDENLAMP)
    {
        l2h_expected_mode = L2H_MODE_ON;
    }

    data[0] = l2h_expected_mode;
    data[1] = power ? 0xFF : 0x00;

    net->type = L2H_NET_SSL;
    l2h_send_request(net, L2H_CMD_STATUS_05, data, 2);
    l2h_send_request(net, L2H_CMD_SWITCH_REPORT, data, 2);
}

void l2h_send_idle(l2h_net_t *net)
{
    l2h_send_status(net);
    l2h_send_request(net, L2H_CMD_IDLE, (uint8_t *)"", 0);
}

void l2h_send_login(l2h_net_t *net)
{
    net->type = L2H_NET_SSL;
    l2h_send_request(net, L2H_CMD_LOGIN, (uint8_t *)"\x08\x00\x00\x01\x5b\x8f\xf1\x3b\x43", 9);
}
