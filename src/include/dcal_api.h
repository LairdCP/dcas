/*
Copyright (c) 2016, Laird
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

// This header file is for use in end users applications which utilize
// the Laird DCAL API to setup and get status from Laird workplace bridges

#ifndef _DCAL_API_
#define _DCAL_API_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "sdc_sdk_legacy.h"

#define DCAL_API_VERSION 0x01010101

typedef enum _DCAL_ERR{
	DCAL_SUCCESS = 0,
	DCAL_INVALID_PARAMETER,
	DCAL_INVALID_HANDLE,
	DCAL_HANDLE_IN_USE,
	DCAL_HANDLE_NOT_ACTIVE,
	DCAL_NO_NETWORK_ACCESS,
	DCAL_NO_MEMORY,
	DCAL_NOT_IMPLEMENTED,
	DCAL_SSH_ERROR,
	DCAL_FLATBUFF_ERROR,
	DCAL_FLATCC_NOT_INITIALIZED,
	DCAL_SDK_ERROR = 100,
} DCAL_ERR;

typedef char * FQDN;

typedef void * laird_session_handle;

#define MAC_SZ 6
#define IP4_SZ 4
#define IP6_STR_SZ 46 //max string:0000:0000:0000:0000:0000:0000:xxx.xxx.xxx.xxx plus NULL (IPV4 mapped IPV6 address)
#define NAME_SZ 48
#define SSID_SZ 32

typedef struct _laird_status_struct {
	unsigned int cardState;
	char ProfileName[NAME_SZ];
	char ssid[SSID_SZ]; //32 characters.  Can contain non-ascii characters.  Not necessarily NULL terminated. Use ssid_len to access data.
	unsigned int ssid_len;
	unsigned int channel;
	int rssi;
	char clientName[NAME_SZ];
	unsigned char mac[MAC_SZ];
	unsigned char ipv4[IP4_SZ];
	char ipv6[IP6_STR_SZ];
	unsigned char ap_mac[MAC_SZ];
	unsigned char ap_ip[MAC_SZ];
	char ap_name[NAME_SZ];
	unsigned int bitRate;
	unsigned int txPower;
	unsigned int dtim;
	unsigned int beaconPeriod;
} DCAL_STATUS_STRUCT;

// API session management

DCAL_ERR dcal_session_create( laird_session_handle * session);
DCAL_ERR dcal_set_host( laird_session_handle session, FQDN address );
DCAL_ERR dcal_set_port( laird_session_handle session, unsigned int port );
DCAL_ERR dcal_set_user( laird_session_handle session, char * user );
DCAL_ERR dcal_set_pw( laird_session_handle session, char * pw );
//TODO DCAL_ERR dcal_set_key( laird_session_handle session, char * keydata, int size);
DCAL_ERR dcal_session_open ( laird_session_handle session );
DCAL_ERR dcal_session_close( laird_session_handle session);

// Device Status

DCAL_ERR dcal_device_status( laird_session_handle session, DCAL_STATUS_STRUCT * status_struct);

// WiFi Management
//TODO

// WiFi Profile Management
//TODO

// interesting stuff

const char *dcal_err_to_string( DCAL_ERR code);

#ifdef __cplusplus
}
#endif
#endif //_DCAL_API_
