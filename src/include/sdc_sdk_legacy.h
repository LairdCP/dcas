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

/*
This file only exists temporarily to provide some constants and structures
that will later be provided by a proper schema. It shouldn't be relied upon as
it will be removed ASAP.

The constants and structures herein come from sdc_sdk.h. The full header may be
found in our Linux MSD release packages.
*/

#ifndef _SDC_SDK_H_
#define _SDC_SDK_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _AUTH {
	AUTH_OPEN = 0,
	AUTH_SHARED,
	AUTH_NETWORK_EAP,
} AUTH;

typedef enum _EAPTYPE {
	EAP_NONE = 0,
	EAP_LEAP,
	EAP_EAPFAST,
	EAP_PEAPMSCHAP,
	EAP_PEAPGTC,
	EAP_EAPTLS,
	EAP_EAPTTLS,
	EAP_PEAPTLS,
	EAP_WAPI_CERT
} EAPTYPE;

typedef enum _POWERSAVE {
	POWERSAVE_OFF = 0,
	POWERSAVE_MAX,
	POWERSAVE_FAST,
} POWERSAVE;

typedef enum _WEPTYPE {
	WEP_OFF = 0,
	WEP_ON,
	WEP_AUTO,
	WPA_PSK,
	WPA_TKIP,
	WPA2_PSK,
	WPA2_AES,
	CCKM_TKIP,
	WEP_CKIP,
	WEP_AUTO_CKIP,
	CCKM_AES,
	WPA_PSK_AES,
	WPA_AES,
	WPA2_PSK_TKIP,
	WPA2_TKIP,
	WAPI_PSK,
	WAPI_CERT
} WEPTYPE;

typedef enum _RADIOMODE {
	RADIOMODE_B_ONLY = 0,
	RADIOMODE_BG,
	RADIOMODE_G_ONLY,
	RADIOMODE_BG_LRS,
	RADIOMODE_A_ONLY,
	RADIOMODE_ABG,
	RADIOMODE_BGA,
	RADIOMODE_ADHOC,
	RADIOMODE_GN,
	RADIOMODE_AN,
	RADIOMODE_ABGN,
	RADIOMODE_BGAN,
	RADIOMODE_BGN
} RADIOMODE;

typedef enum _RADIOCHIPSET {
	RADIOCHIPSET_NONE     = 0,
	RADIOCHIPSET_SDC10    = 1, //BCM4318
	RADIOCHIPSET_SDC15    = 2, //BCM4322,
	RADIOCHIPSET_SDC30    = 3, //AR6002,
	RADIOCHIPSET_SDC40L   = 4, //BCM4319,
	RADIOCHIPSET_SDC40NBT = 5, //BCM4329,
	RADIOCHIPSET_SDC45    = 6, //AR6003,
	RADIOCHIPSET_SDC50    = 7, //AR6004,
} RADIOCHIPSET;

typedef int32_t LRD_SYSTEM;

// 32 bits
// 8 bits are chipset <=> RADIOCHIPSET enum
// 4 bits are family  <=> WB, MSD/SSD
// 4 bits are HW version -- hardware version
// 4 bits are Struct version -- structure version
// 11 bits for reserved
// 1 bit = driver loaded  (0==not loaded, 1== loaded)

#define LRD_SYS_FAM_WB                     1
#define LRD_SYS_FAM_MSD_SSD                2

#define RADIOCHIPSET_from_LRD_SYSTEM(sys)  (int)(sys & 0x000000fful)
#define LRD_SYSTEM_family(sys)             (int)((sys & 0x00000f00ul) >> 8)
#define LRD_SYSTEM_hw_version(sys)         (int)((sys & 0x0000f000ul) >> 12)
#define LRD_SYSTEM_struct_version(sys)     (int)((sys & 0x000f0000ul) >> 16)
#define LRD_SYSTEM_DriverLoaded(sys)       (int)((sys & 0x80000000ul) >> 31)

typedef enum _BITRATE {
	BITRATE_AUTO  = 0,
	//rates from 802.11 - 1997
	BITRATE_1     = 2,
	BITRATE_2     = 4,
	// additional rates from 802.11b
	BITRATE_5_5   = 11,
	BITRATE_11    = 22,
	// additional rates from 802.11g
	BITRATE_6     = 12,
	BITRATE_9     = 18,
	BITRATE_12    = 24,
	BITRATE_18    = 36,
	BITRATE_24    = 48,
	BITRATE_36    = 72,
	BITRATE_48    = 96,
	BITRATE_54    = 108,
	// additional rates from 802.11n 20Mhz channel Short Guard Interval (SGI) disabled
	BITRATE_6_5   = 13,
	BITRATE_13    = 26,
	BITRATE_19_5  = 39,
	BITRATE_26    = 52,
	BITRATE_39    = 78,
	BITRATE_52    = 104,
	BITRATE_58_5  = 117,
	// additional rates for 2 streams
	BITRATE_78    = 156,
	BITRATE_104   = 208,
	BITRATE_117   = 234,
	BITRATE_130   = 260,
	// additional rates from 802.11n 20Mhz channel Short Guard Interval (SGI) enabled
	BITRATE_7_2   = 14,
	BITRATE_14_4  = 28,
	BITRATE_21_7  = 42,
	BITRATE_28_9  = 56,
	BITRATE_43_3  = 86,
	BITRATE_57_8  = 114,
	BITRATE_65    = 130,
	BITRATE_72    = 144,
	// additional rates for 2 streams
	BITRATE_86_7  = 173,
	BITRATE_115_6 = 231,
//BITRATE_130   = 260,
	BITRATE_144_4 = 288,
	// additional rates from 802.11n 40Mhz channel Short Guard Interval (SGI) disabled
	BITRATE_13_5  = 27,
	BITRATE_27    = 54,
	BITRATE_40_5  = 81,
	BITRATE_81    = 162,
	BITRATE_108   = 216,
	BITRATE_121_5 = 243,
	BITRATE_135   = 270,
	// additional rates for 2 streams
	BITRATE_162   = 324,
	BITRATE_216   = 432,
	BITRATE_243   = 486,
	BITRATE_270   = 540,
	// additional rates from 802.11n 40Mhz channel Short Guard Interval (SGI) enabled
	BITRATE_15    = 30,
	BITRATE_30    = 60,
	BITRATE_45    = 90,
	BITRATE_60    = 120,
	BITRATE_90    = 180,
	BITRATE_120   = 240,
	BITRATE_150   = 300,
	// additional rates for 2 streams
	BITRATE_180   = 360,
	BITRATE_240   = 480,
//BITRATE_270   = 540,
	BITRATE_300   = 600,
} BITRATE;
#define LRD_WF_MAX_SSID_LEN    32
#define LRD_WF_MAC_ADDR_LEN    6

typedef struct _LRD_WF_SSID{
	unsigned char len;
	unsigned char val[LRD_WF_MAX_SSID_LEN];
	                                  // Note that the val is not a string
	                                  // and can have embedded NULL and non-
	                                  // printable characters.  Also note
	                                  // that val does not have a null
	                                  // termination character.
} LRD_WF_SSID;


#ifdef __cplusplus
}
#endif
#endif//_SDC_SDK_H_;
