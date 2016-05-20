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
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "sdc_sdk_legacy.h"

#define DCAL_API_VERSION 0x01010101

typedef enum _DCAL_ERR{
	DCAL_SUCCESS = 0,
	// save room for SDK errors
	DCAL_INVALID_PARAMETER = 100,
	DCAL_INVALID_HANDLE,
	DCAL_HANDLE_IN_USE,
	DCAL_HANDLE_NOT_ACTIVE,
	DCAL_NO_NETWORK_ACCESS,
	DCAL_NO_MEMORY,
	DCAL_NOT_IMPLEMENTED,
	DCAL_INVALID_CONFIGURATION,
	DCAL_SSH_ERROR,
	DCAL_FLATBUFF_ERROR,
	DCAL_FLATCC_NOT_INITIALIZED,
	DCAL_FLATBUFF_VALIDATION_FAIL,
} DCAL_ERR;

typedef char * FQDN;

typedef void * laird_session_handle;
typedef void * laird_profile_handle;

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

#define STR_SZ 80
typedef struct _laird_version_struct {
	unsigned int sdk;
	RADIOCHIPSET chipset;
	LRD_SYSTEM sys;
	unsigned int driver;
	unsigned int dcas;
	unsigned int dcal;
	char firmware[STR_SZ];
	char supplicant[STR_SZ];
	char release[STR_SZ];
} DCAL_VERSION_STRUCT;

// API session management

int dcal_session_create( laird_session_handle * session);
int dcal_set_host( laird_session_handle session, FQDN address );
int dcal_set_port( laird_session_handle session, unsigned int port );
int dcal_set_user( laird_session_handle session, char * user );
int dcal_set_pw( laird_session_handle session, char * pw );
//TODO int dcal_set_key( laird_session_handle session, char * keydata, int size);
int dcal_session_open ( laird_session_handle session );
int dcal_session_close( laird_session_handle session);

// Device Versions
int dcal_device_version( laird_session_handle session, DCAL_VERSION_STRUCT * version_struct);

// Device Status
int dcal_device_status( laird_session_handle session, DCAL_STATUS_STRUCT * status_struct);

// WiFi Management
int dcal_wifi_enable( laird_session_handle session);
int dcal_wifi_disable( laird_session_handle session);

// WiFi Profile Management_
// both the create and pull functions will allocate a laird_profile_handle that require the close_handle function to be called when done with then handle
int dcal_wifi_profile_create( laird_profile_handle * profile);
int dcal_wifi_profile_pull( laird_session_handle session,
                                 laird_profile_handle profile,
                                 char * profilename);
int dcal_wifi_profile_close_handle( laird_profile_handle profile);

//    push and profile_activate both send the local profile to the remote radio device.  Activate_by_name only activates the named profile on the remote radio
int dcal_wifi_profile_push( laird_session_handle session,
                                 laird_profile_handle profile);
int dcal_wifi_profile_activate( laird_session_handle sesion,
                                     laird_profile_handle profile);
int dcal_wifi_profile_activate_by_name( laird_session_handle session,
                                          char * profile_name);

int dcal_wifi_profile_set_profilename(laird_profile_handle profile,
                                           char * profilename );
int dcal_wifi_profile_get_profilename(laird_profile_handle profile,
                                           char * profilename );

// note the SSID is not a string as SSIDs can contain embedded non-ascii characters including embedded nulls  (the SDK on the device may not yet support non-ascii characters)
int dcal_wifi_profile_set_SSID( laird_profile_handle profile,
                                       LRD_WF_SSID *ssid);
int dcal_wifi_profile_get_SSID( laird_profile_handle profile,
                                       LRD_WF_SSID *ssid);

typedef enum _encyption_standards {
	ES_NONE = 0,
	ES_WEP,
	ES_WPA,
	ES_WPA2,
	ES_CCKM
} ENCRYPT_STD;

// security
// setting an encryption standard will clear all security fields
int dcal_wifi_profile_set_encrypt_std( laird_profile_handle profile,
                                            ENCRYPT_STD estd);
int dcal_wifi_profile_get_encrypt_std( laird_profile_handle profile,
                                            ENCRYPT_STD *estd);
typedef enum _encryption {
	ENC_NONE = 0,
	ENC_AES,
	ENC_TKIP,
} ENCRYPTION;

int dcal_wifi_profile_set_encryption( laird_profile_handle profile,
                                           ENCRYPTION enc);
int dcal_wifi_profile_get_encryption( laird_profile_handle profile,
                                           ENCRYPTION *enc);

int dcal_wifi_profile_set_auth( laird_profile_handle profile,
                                     AUTH auth);
int dcal_wifi_profile_get_auth( laird_profile_handle profile,
                                     AUTH *auth);

int dcal_wifi_profile_set_eap( laird_profile_handle profile,
                                    EAPTYPE eap);
int dcal_wifi_profile_get_eap( laird_profile_handle profile,
                                    EAPTYPE *eap);

int dcal_wifi_profile_set_psk( laird_profile_handle profile,
                                    char * psk);
int dcal_wifi_profile_get_psk( laird_profile_handle profile,
                                    char * psk_buffer);

int dcal_wifi_profile_set_user( laird_profile_handle profile,
                                     char * user);
int dcal_wifi_profile_get_user( laird_profile_handle profile,
                                     char * user_buffer);

int dcal_wifi_profile_set_password( laird_profile_handle profile,
                                         char * password);
int dcal_wifi_profile_get_password( laird_profile_handle profile,
                                         char * password_buffer);

int dcal_wifi_profile_set_cacert( laird_profile_handle profile,
                                       char * cacert);
int dcal_wifi_profile_get_cacert( laird_profile_handle profile,
                                       char * cacert_buffer);

int dcal_wifi_profile_set_pacfile( laird_profile_handle profile,
                                 char * pacfilename);
int dcal_wifi_profile_get_pacfile( laird_profile_handle profile,
                                 char * pacfilename_buffer);

int dcal_wifi_profile_set_pacpassword( laird_profile_handle profile,
                                 char * pacpassword);
int dcal_wifi_profile_get_pacpassword( laird_profile_handle profile,
                                 char * pacpassword_buffer);

int dcal_wifi_profile_set_usercert( laird_profile_handle profile,
                                 char * usercert);
int dcal_wifi_profile_get_usercert( laird_profile_handle profile,
                                 char * usercert_buffer);

int dcal_wifi_profile_set_usercert_password( laird_profile_handle profile,
                                 char * usercert_password);
int dcal_wifi_profile_get_usercert_password( laird_profile_handle profile,
                                 char * usercert_password_buffer);

int dcal_wifi_profile_set_wep_key( laird_profile_handle profile,
                                 char * wepkey, int index);
int dcal_wifi_profile_get_wep_key( laird_profile_handle profile,
                                 char * wepkey_buffer, int index);

int dcal_wifi_profile_set_wep_txkey( laird_profile_handle profile,
                                 unsigned int txkey);
int dcal_wifi_profile_get_wep_txkey( laird_profile_handle profile,
                                 unsigned int *txkey);

// other profile settings

int dcal_wifi_profile_set_clientname( laird_profile_handle profile,
                                char * clientname);
int dcal_wifi_profile_get_clientname( laird_profile_handle profile,
                                char * clientname_buffer);

int dcal_wifi_profile_set_radionmode( laird_profile_handle profile,
                                RADIOMODE mode);
int dcal_wifi_profile_get_radionmode( laird_profile_handle profile,
                                RADIOMODE * mode);

int dcal_wifi_profile_set_powersave( laird_profile_handle profile,
                               POWERSAVE powersave);
int dcal_wifi_profile_get_powersave( laird_profile_handle profile,
                               POWERSAVE * powersave);

int dcal_wifi_profile_set_psp_delay( laird_profile_handle profile,
                               unsigned int pspdelay);
int dcal_wifi_profile_get_psp_delay( laird_profile_handle profile,
                               unsigned int * pspdelay);

int dcal_wifi_profile_set_txpower( laird_profile_handle profile,
                               int txpower);
int dcal_wifi_profile_get_txpower( laird_profile_handle profile,
                               int *txpower);

int dcal_wifi_profile_set_bitrate( laird_profile_handle profile,
                               BITRATE bitrate);
int dcal_wifi_profile_get_bitrate( laird_profile_handle profile,
                               BITRATE *bitrate);

int dcal_wifi_profile_set_profile( laird_profile_handle profile,
                               bool autoprofile);
int dcal_wifi_profile_get_profile( laird_profile_handle profile,
                               bool *autoprofile);

void dcal_wifi_profile_printf( laird_profile_handle profile);

// interesting stuff

const char *dcal_err_to_string( int code);

#ifdef __cplusplus
}
#endif
#endif //_DCAL_API_
