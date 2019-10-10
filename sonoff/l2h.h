#ifndef _L2H_H_
#define _L2H_H_

#include <stdint.h>

#ifdef PC
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#endif


/* identification response */
#define L2H_VER_HW "HW_V1.00"
#define L2H_VER_SW "1.12"
#define L2H_TZ     "Europe/Berlin"
#define L2H_CITYID "U0XVNRXKNRPH"
#define L2H_COORD  "11.185068,48.802525"


/* emulated device types, there are a few more */
#define L2H_DEVICE_SWITCH     0xD1
#define L2H_DEVICE_GARDENLAMP 0xe3


/* constants */
#define L2H_MAX_PKT_LEN 1024

#define L2H_MODE_SESNOR   0
#define L2H_MODE_ON       1
#define L2H_MODE_OFF      2
#define L2H_MODE_TIMED    3
#define L2H_MODE_RANDOM   4

/* command IDs */
#define L2H_CMD_SWITCH         0x01
#define L2H_CMD_UNK_02         0x02
#define L2H_CMD_SWITCH_REPORT  0x03
#define L2H_CMD_SCHED          0x04
#define L2H_CMD_STATUS_05      0x05
#define L2H_CMD_COUNTDOWN      0x07
#define L2H_CMD_UNK_08         0x08
#define L2H_CMD_UNK_0B         0x0B
#define L2H_CMD_SET_ALLID      0x0F
#define L2H_CMD_ALLID          0x10
#define L2H_CMD_UNK_12         0x12
#define L2H_CMD_UNPAIR_14      0x14
#define L2H_CMD_ANNCOUNCE      0x23
#define L2H_CMD_PAIR_24        0x24
#define L2H_CMD_BALANCE        0x41
#define L2H_CMD_LOGIN          0x42
#define L2H_CMD_CITYID         0x44
#define L2H_CMD_ZONEID         0x45
#define L2H_CMD_LUMEN          0x46 /* 1 byte data */
#define L2H_CMD_COLWHITE       0x47 /* 1 byte data */
#define L2H_CMD_COLRGB         0x48 /* 3 byte data */
#define L2H_CMD_MAXBR          0x49 /* 1 byte data, 00 = low, c8 = max */
#define L2H_CMD_LUMDUR         0x50 /* 1 byte data */
#define L2H_CMD_SENSLVL        0x51 /* 1 byte data */
#define L2H_CMD_LUX            0x52 /* 2 byte data */
#define L2H_CMD_ONDUR          0x53 /* 2 byte data */
#define L2H_CMD_UNK_56         0x56
#define L2H_CMD_SENSMODE       0x58
#define L2H_CMD_TEST           0x59
#define L2H_CMD_UNK_5B         0x5B /* 1 byte data */
#define L2H_CMD_LAMPMODE       0x55 /* 1 byte data, 00 = sensor, 01 = on, 02 = off, 03 = timed, 04 = random */
#define L2H_CMD_PANIC          0x5C /* 1 byte data, 00 = off, 01 = on */
#define L2H_CMD_IDLE           0x61
#define L2H_CMD_VERSION        0x62
#define L2H_CMD_FWUP           0x63


#define L2H_PKT_HDR            0xA1
#define L2H_PKT_DIRECT         0x00
#define L2H_PKT_REQUEST        0x04
#define L2H_PKT_RESPONSE       0x02

typedef struct
{
    uint8_t hdr;
    uint8_t type;
    uint8_t mac[6];
    uint16_t length;
    uint16_t sequence;
    uint8_t companyCode;
    uint8_t deviceType;
    uint16_t authCode;
} l2h_hdr_t;



#define L2H_NET_SSL   0
#define L2H_NET_UDP   1
#define L2H_NET_BCAST 2

typedef struct
{
    uint8_t type;
    uint8_t ip[4];
} l2h_net_t;


uint32_t pa_time();
uint32_t pa_ssl_read(l2h_net_t *net, uint8_t *buf, uint32_t length);
uint32_t pa_ssl_write(l2h_net_t *net, uint8_t *buf, uint32_t length);
uint32_t pa_udp_write(l2h_net_t *net, uint8_t *buf, uint32_t length);
uint32_t pa_udp_read(l2h_net_t *net, uint8_t *buf, uint32_t length);
uint32_t pa_bcast_write(l2h_net_t *net, uint8_t *buf, uint32_t length);


uint8_t *l2h_get_payload(l2h_hdr_t *pkt);
uint8_t *l2h_get_data(l2h_hdr_t *pkt);
uint8_t l2h_get_cmd(l2h_hdr_t *pkt);
void l2h_packet_free(l2h_hdr_t *pkt);
void l2h_dump_pkt(l2h_hdr_t *pkt, const char *msg);
l2h_hdr_t *l2h_read(l2h_net_t *net);
l2h_hdr_t *l2h_packet_alloc(uint16_t len);
l2h_hdr_t *l2h_packet_alloc_request(uint8_t command, uint8_t *payload, uint16_t payload_len);
l2h_hdr_t *l2h_packet_alloc_response(l2h_hdr_t *ref_pkt, uint8_t *payload, uint16_t payload_len);
void l2h_write(l2h_net_t *net, l2h_hdr_t *pkt);
void l2h_send_response(l2h_net_t *net, l2h_hdr_t *ref_pkt, uint8_t *payload, uint16_t payload_len);
void l2h_send_request(l2h_net_t *net, uint8_t command, uint8_t *payload, uint16_t payload_len);
void l2h_handle(l2h_net_t *net, l2h_hdr_t *pkt);
void l2h_send_idle(l2h_net_t *net);
void l2h_send_login(l2h_net_t *net);


#endif

