#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libgen.h>

#include "debug.h"
#include "sdc_sdk.h"
#include "lrd_sdk_eni.h"
#include "buffer.h"
#include "dcal_api.h"
#include "version.h"

#include "dcal_builder.h"
#include "dcal_verifier.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)
#include "flatcc/support/hexdump.h"

#define LAIRD_HELLO "HELLO DCAS"
#define LAIRD_RESPONSE "WELCOME TO FAIRFIELD"
#define LAIRD_BAD_BUFFER "BAD FLAT BUFFER"

#define SDKLOCK(x) (pthread_mutex_lock(x))
#define SDKUNLOCK(x) (pthread_mutex_unlock(x))
#define TMPDIR "/tmp"

#define safe_free(x) do{if(x){free(x); x=NULL;}}while (0)

#define SZ_1K 1024
#define FILEBUFSZ (SZ_1K * 128)

// a 0 return code means invalid buffer
flatbuffers_thash_t verify_buffer(const void * buf, const size_t size)
{
	flatbuffers_thash_t ret;
	if ((buf==NULL) || (size==0))
		return 0;

	ret = flatbuffers_get_type_hash(buf);
	switch(ret) {
		case ns(Handshake_type_hash):
			if(ns(Handshake_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Status_type_hash):
			if(ns(Status_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Command_type_hash):
			if(ns(Command_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(U32_type_hash):
			if(ns(U32_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Version_type_hash):
			if(ns(Version_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Globals_type_hash):
			if(ns(Globals_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Profile_type_hash):
			if(ns(Profile_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(P_entry_type_hash):
			if(ns(P_entry_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Profile_list_type_hash):
			if(ns(Profile_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Interface_type_hash):
			if(ns(Interface_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Lease_type_hash):
			if(ns(Lease_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Default_route_type_hash):
			if(ns(Default_route_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Time_type_hash):
			if(ns(Time_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Filexfer_type_hash):
			if(ns(Filexfer_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Scan_item_type_hash):
			if(ns(Scan_item_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		case ns(Scan_list_type_hash):
			if(ns(Scan_item_verify_as_root(buf,size))){
				DBGERROR("line %d: unable to verify buffer\n", __LINE__);
				ret = 0;
				}
			break;
		default:
			DBGERROR("%s: buffer hash invalid: %lx\n", __func__, (unsigned long)ret);
			ret = 0;
	}
	return ret;
}

const char * buftype_to_string(flatbuffers_thash_t buftype)
{
	switch(buftype) {
		case ns(Handshake_type_hash):
			return "Handshake";
			break;
		case ns(Status_type_hash):
			return "Status";
			break;
		case ns(Command_type_hash):
			return "Command";
			break;
		case ns(U32_type_hash):
			return "U32";
			break;
		case ns(Version_type_hash):
			return "Version";
			break;
		case ns(Globals_type_hash):
			return "Globals";
			break;
		case ns(Profile_type_hash):
			return "Profile";
			break;
		case ns(P_entry_type_hash):
			return "Profile list entry";
			break;
		case ns(Profile_list_type_hash):
			return "Profile list";
			break;
		case ns(Interface_type_hash):
			return "Interface";
			break;
		case ns(Lease_type_hash):
			return "Lease";
			break;
		case ns(Default_route_type_hash):
			return "Default route";
			break;
		case ns(Time_type_hash):
			return "Time";
			break;
		case ns(Filexfer_type_hash):
			return "Filexfer";
			break;
		case ns(Scan_item_type_hash):
			return "Scan_item";
			break;
		case ns(Scan_list_type_hash):
			return "Scan_list";
			break;

		default:
			return("unrecognized\n");
	}
}

int is_handshake_valid( ns(Handshake_table_t) handshake)
{
	#ifdef DEBUG_BUILD
	const char * ip;
	#endif
	int ret;

	if (ns(Handshake_server(handshake)) == true) {
		DBGERROR("Handshake marked as from server\n");
		return 0;
	}

	#ifdef DEBUG_BUILD
	ip = ns(Handshake_ip(handshake));
	#endif
	DBGINFO("Handshake ip: %s\n", ip);

	if (ns(Handshake_magic(handshake)) == ns(Magic_HELLO))
		return 1;

	return 0;
}

int build_handshake_ack(flatcc_builder_t *B, unsigned int error)
{
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Handshake_type_identifier));
	ns(Handshake_start(B));
	ns(Handshake_server_add(B, true));

	if (error)
		ns(Handshake_magic_add(B, ns(Magic_NACK)));
	else
		ns(Handshake_magic_add(B, ns(Magic_ACK)));

	//TODO - do we want our ip address in the handshake from server?  If so
	//we need to get from the ssh session somehow so we know what interface
	//Could have it included by default in process_buffer call
//	ns(Handshake_ip_create_str(B, "192.168.0.1"));
	ns(Handshake_api_level_add(B, DCAL_VERSION));
	ns(Handshake_error_add(B, error));
	ns(Handshake_end_as_root(B));

	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int build_status(flatcc_builder_t *B, pthread_mutex_t *sdk_lock)
{
	CF10G_STATUS status = {0};

	status.cardState = CARDSTATE_AUTHENTICATED;
	SDCERR result;
	LRD_WF_SSID ssid = {0};
	LRD_WF_ipv6names *ipv6_names = NULL;
	size_t num_ips = 0;

	SDKLOCK(sdk_lock);
	result = GetCurrentStatus(&status);
	SDKUNLOCK(sdk_lock);
	if (result!=SDCERR_SUCCESS){
		DBGERROR("GetCurrentStatus() failed with %d\n", result);
		return result;
	}
	SDKLOCK(sdk_lock);
	result = LRD_WF_GetSSID(&ssid);
	SDKUNLOCK(sdk_lock);
	if (result!=SDCERR_SUCCESS){
		// there are conditions such as disabled where this could fail
		// and we don't want to abort sending back status, so no return
		// here - just log it.
		DBGINFO("LRD_WF_GetSSID() failed with %d\n", result);
	}

// only dealing with client mode for now
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Status_type_identifier));
	ns(Status_start(B));
	ns(Status_cardState_add(B, status.cardState));
	ns(Status_ProfileName_create_str(B, status.configName));
	if (ssid.len > LRD_WF_MAX_SSID_LEN)
		ssid.len = LRD_WF_MAX_SSID_LEN;  // should never happen
	ns(Status_ssid_create(B, (unsigned char *)ssid.val, ssid.len));
	ns(Status_channel_add(B, status.channel));
	ns(Status_rssi_add(B, status.rssi));
	ns(Status_clientName_create_str(B, status.clientName));
	ns(Status_mac_create(B, (unsigned char *)status.client_MAC, MAC_SZ));
	ns(Status_ip_create(B, (unsigned char *)status.client_IP, IP4_SZ));
	ns(Status_AP_mac_create(B, (unsigned char *)status.AP_MAC, MAC_SZ));
	ns(Status_AP_ip_create(B, (unsigned char *)status.AP_IP, IP4_SZ));
	ns(Status_AP_name_create_str(B, status.APName));
	ns(Status_bitRate_add(B, status.bitRate));
	ns(Status_txPower_add(B, status.txPower));
	ns(Status_dtim_add(B, status.DTIM));
	ns(Status_beaconPeriod_add(B, status.beaconPeriod));

	SDKLOCK(sdk_lock);
	result = LRD_WF_GetIpV6Address(NULL, &num_ips);
	ipv6_names = (LRD_WF_ipv6names*)malloc(sizeof(LRD_WF_ipv6names)*(num_ips+3));
	if (ipv6_names==NULL){
		SDKUNLOCK(sdk_lock);
		return SDCERR_INSUFFICIENT_MEMORY;
	}
	result = LRD_WF_GetIpV6Address(ipv6_names, &num_ips);
	SDKUNLOCK(sdk_lock);
	if(result!=SDCERR_SUCCESS){
		free(ipv6_names);
		return result;
	}
	flatbuffers_string_vec_ref_t flatc_ipnames[num_ips];

	for (size_t i=0; i< num_ips; i++)
		flatc_ipnames[i]=flatbuffers_string_create_str(B, ipv6_names[i]);
	flatbuffers_string_vec_ref_t fcv_addresses = flatbuffers_string_vec_create(B, flatc_ipnames, num_ips);

	ns(Status_ipv6_add(B, fcv_addresses));

	ns(Status_end_as_root(B));

	free(ipv6_names);
	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int build_version(flatcc_builder_t *B, pthread_mutex_t *sdk_lock)
{
	SDCERR result;
	CF10G_STATUS status = {0};
	unsigned long longsdk = 0;
	int size = STR_SZ;
	RADIOCHIPSET chipset;
	LRD_SYSTEM sys;
	int sdk;
	unsigned int driver;
	unsigned int dcas;
	unsigned int dcal;
	char firmware[STR_SZ];
	char supplicant[STR_SZ];
	char release[STR_SZ];

	inline void remove_cr(char * str)
	{
		int i;
		for (i=0; i<STR_SZ; i++)
			if (str[i]==0xa)
				str[i]=0;
	}

	SDKLOCK(sdk_lock);
	result = GetCurrentStatus(&status);
	if (result == SDCERR_SUCCESS)
		result = GetSDKVersion(&longsdk);
	if (result == SDCERR_SUCCESS)
		result = LRD_WF_GetRadioChipSet(&chipset);
	if (result == SDCERR_SUCCESS)
		result = LRD_WF_System_ID(&sys);
	if (result == SDCERR_SUCCESS)
		result = LRD_WF_GetFirmwareVersionString(firmware, &size);
	SDKUNLOCK(sdk_lock);
	if (result)
		return result;

	sdk = longsdk;
	dcas = DCAS_COMPONENT_VERSION;
	driver = status.driverVersion;

	FILE *in = popen( "sdcsupp -qv", "r");
	if (in){
		if (fgets(supplicant, STR_SZ, in) == NULL)
			supplicant[0]=0;
		pclose(in);
	} else
		strcpy(supplicant, "none");

	int sysfile = open ("/etc/laird-release", O_RDONLY);
	if ((sysfile==-1) && (errno==ENOENT))
		sysfile = open ("/etc/summit-release", O_RDONLY);
	if (sysfile > 1){
		if (read(sysfile, release, STR_SZ) < 0)
			release[0]=0;
		release[STR_SZ-1]=0;
		close(sysfile);
	}else
		strcpy(release, "unknown");

/// have various versions - now build buffer
	remove_cr(supplicant);
	remove_cr(release);

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Version_type_identifier));
	ns(Version_start(B));
	ns(Version_sdk_add(B, sdk));
	ns(Version_chipset_add(B, chipset));
	ns(Version_sys_add(B, sys));
	ns(Version_driver_add(B, driver));
	ns(Version_dcas_add(B, dcas));
	ns(Version_firmware_create_str(B, firmware));
	ns(Version_supplicant_create_str(B, supplicant));
	ns(Version_release_create_str(B, release));

	ns(Version_end_as_root(B));

	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_enable_disable(flatcc_builder_t *B, pthread_mutex_t *sdk_lock, bool enable)
{
	SDCERR result;
	SDKLOCK(sdk_lock);
		if (enable)
			result = RadioEnable();
		else
			result = RadioDisable();
	SDKUNLOCK(sdk_lock);

	if (result != SDCERR_SUCCESS)
		return result;

	build_handshake_ack(B, 0);
	return 0;
}

#define user(p) (char*)ns(Profile_security1(p))
#define password(p) (char*)ns(Profile_security2(p))
#define psk(p) (char*)ns(Profile_security1(p))
#define cacert(p) (char*)ns(Profile_security3(p))
#define pacfilename(p) (char*)ns(Profile_security3(p))
#define pacpassword(p) (char*)ns(Profile_security4(p))
#define usercert(p) (char*)ns(Profile_security4(p))
#define usercertpassword(p) (char*)ns(Profile_security5(p))

#define weplen(s) ((strlen(s)==5)?WEPLEN_40BIT:(strlen(s)==13)?WEPLEN_128BIT:WEPLEN_NOT_SET)

SDCERR LRD_WF_AutoProfileCfgControl(const char *name, unsigned char enable);
SDCERR LRD_WF_AutoProfileCfgStatus(const char *name, unsigned char *enabled);
SDCERR LRD_WF_AutoProfileControl(unsigned char enable);
SDCERR LRD_WF_AutoProfileStatus(unsigned char *enable);

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_set_profile(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(Profile_table_t) profile;
	SDCConfig config = {{0}};
	int ret;

	//TODO we ought to do some assertion that the cmd_table is a profile
	profile = ns(Command_cmd_pl(cmd));

	strncpy(config.configName, ns(Profile_name(profile)), CONFIG_NAME_SZ - 1);
	assert(flatbuffers_uint8_vec_len(ns(Profile_ssid(profile))) <= SSID_SZ);

	memcpy(&config.SSID, ns(Profile_ssid(profile)), flatbuffers_uint8_vec_len(ns(Profile_ssid(profile))));

	strncpy(config.clientName, ns(Profile_client_name(profile)), CLIENT_NAME_SZ - 1);

	config.txPower = ns(Profile_txPwr(profile));
	config.authType = ns(Profile_auth(profile));
	config.eapType = ns(Profile_eap(profile));
	config.powerSave = ns(Profile_pwrsave(profile));
	config.powerSave |= (ns(Profile_pspDelay(profile)) << 16);
	config.wepType = ns(Profile_weptype(profile));
	config.bitRate = ns(Profile_bitrate(profile));
	config.radioMode = ns(Profile_radiomode(profile));

	switch(config.wepType) {
		case WEP_ON:
			ret = SetMultipleWEPKeys( &config, ns(Profile_weptxkey(profile)),
			                weplen(ns(Profile_security1(profile))),
			                (unsigned char*)ns(Profile_security1(profile)),
			                weplen(ns(Profile_security2(profile))),
			                (unsigned char*)ns(Profile_security2(profile)),
			                weplen(ns(Profile_security3(profile))),
			                (unsigned char*)ns(Profile_security3(profile)),
			                weplen(ns(Profile_security4(profile))),
			                (unsigned char*)ns(Profile_security4(profile)));

			if (ret){
				DBGERROR("%s: SetMultipleWEPKeys() failed with %d\n", __func__, ret);
				goto earlyexit;
			}
			break;

		case WPA_PSK:
		case WPA2_PSK:
		case WPA_PSK_AES:
		case WAPI_PSK:
			SetPSK(&config, (char*) psk(profile));
			break;

		case WEP_OFF:
			// dont set any security elements
			break;
		default:
			switch(config.eapType){
				case EAP_LEAP:
					SetLEAPCred(&config, user(profile), password(profile));
					break;
				case EAP_EAPTTLS:
					SetEAPTTLSCred(&config, user(profile), password(profile),
					                CERT_FILE, cacert(profile));
					break;
				case EAP_PEAPMSCHAP:
					SetPEAPMSCHAPCred(&config, user(profile), password(profile),
					               CERT_FILE, cacert(profile));
					break;
				case EAP_PEAPGTC:
					SetPEAPGTCCred(&config, user(profile), password(profile),
					               CERT_FILE, cacert(profile));
					break;
				case EAP_EAPFAST:
					SetEAPFASTCred(&config, user(profile), password(profile),
					               pacfilename(profile), pacpassword(profile));
					break;
				case EAP_EAPTLS:
					SetEAPTLSCred(&config, user(profile), usercert(profile),
					              CERT_FILE, cacert(profile));
					SetUserCertPassword(&config, usercertpassword(profile));
					break;
				case EAP_PEAPTLS:
					SetPEAPTLSCred(&config, user(profile), usercert(profile),
					              CERT_FILE, cacert(profile));
					SetUserCertPassword(&config, usercertpassword(profile));
					break;
				case EAP_NONE:
				case EAP_WAPI_CERT:
				default:
					// do nothing
					break;
			}
			break;
	}

	SDKLOCK(sdk_lock);
	ret = AddConfig(&config);
	if (ret==SDCERR_INVALID_NAME)
		ret = ModifyConfig(config.configName, &config);

	LRD_WF_AutoProfileCfgControl(config.configName, ns(Profile_autoprofile(profile)));
	SDKUNLOCK(sdk_lock);
earlyexit:
	build_handshake_ack(B, ret);
	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_get_profile(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(String_table_t) profile_name;
	SDCConfig config = {{0}};
	int ret;
	unsigned char apStatus = 0;

	//TODO we ought to do some assertion that the cmd_table is a string
	profile_name = ns(Command_cmd_pl(cmd));

	ret = GetConfig((char*) ns(String_value(profile_name)), &config);
	
	if (ret)
		build_handshake_ack(B, ret);
	else
	{
		flatcc_builder_reset(B);
		flatbuffers_buffer_start(B, ns(Profile_type_identifier));
		ns(Profile_start(B));

		ns(Profile_name_create_str(B, config.configName));
		ns(Profile_ssid_create(B, (unsigned char *)config.SSID, strlen(config.SSID)));
		ns(Profile_client_name_create_str(B, config.clientName));
		ns(Profile_txPwr_add(B, config.txPower));
		ns(Profile_pwrsave_add(B, config.powerSave&0xffff));
		ns(Profile_pspDelay_add(B, (config.powerSave >>16)&0xffff));
		ns(Profile_weptype_add(B, config.wepType));
		ns(Profile_auth_add(B, config.authType));
		ns(Profile_eap_add(B, config.eapType));
		ns(Profile_bitrate_add(B, config.bitRate));
		ns(Profile_radiomode_add(B, config.radioMode));
		SDKLOCK(sdk_lock);
		LRD_WF_AutoProfileCfgStatus((char*) ns(String_value(profile_name)), &apStatus);
		SDKUNLOCK(sdk_lock);
		ns(Profile_autoprofile_add(B, apStatus));

		switch(config.wepType){
			case WEP_ON:
			case WEP_CKIP:
			{
				unsigned char key[4][26];
				WEPLEN klen[4];
				int txkey;
				GetMultipleWEPKeys(&config, &txkey, &klen[0], key[0],
					&klen[1], key[1], &klen[2], key[2], &klen[3], key[3]);

				if(klen[0])
					ns(Profile_security1_create_str(B, "1"));
				if(klen[1])
					ns(Profile_security2_create_str(B, "1"));
				if(klen[2])
					ns(Profile_security3_create_str(B, "1"));
				if(klen[3])
					ns(Profile_security4_create_str(B, "1"));
				ns(Profile_weptxkey_add(B, txkey));}
			break;
			case WPA_PSK:
			case WPA2_PSK:
			case WPA_PSK_AES:
			case WPA2_PSK_TKIP:
			case WAPI_PSK:{
				char psk[PSK_SZ] = {0};
				GetPSK(&config, psk);

				if (strlen(psk))
					ns(Profile_security1_create_str(B, "1"));
			}
			break;
			default: { // EAPs
				char user[USER_NAME_SZ] = {0};
				char pw[USER_PWD_SZ] = {0};
				char usercert[CRED_CERT_SZ] = {0};
				char cacert[CRED_CERT_SZ] = {0};
				char pacfn[CRED_PFILE_SZ] = {0};
				char pacpw[CRED_PFILE_SZ] = {0};
				char usercrtpw[USER_PWD_SZ] = {0};

				switch (config.eapType) {
					case EAP_EAPFAST:
						GetEAPFASTCred(&config, user, pw, pacfn, pacpw);
					break;
					case EAP_PEAPMSCHAP:
						GetPEAPMSCHAPCred(&config, user, pw, NULL, cacert);
					break;
					case EAP_EAPTLS:
						GetEAPTLSCred(&config, user, usercert, NULL, cacert);
					break;
					case EAP_EAPTTLS:
						GetEAPTTLSCred(&config, user, usercert, NULL, cacert);
						GetUserCertPassword(&config, usercrtpw);
					break;
					case EAP_PEAPTLS:
						GetPEAPTLSCred(&config, user, usercert, NULL, cacert);
						GetUserCertPassword(&config, usercrtpw);
					break;
					case EAP_LEAP:
						GetLEAPCred(&config, user, pw);
					break;
					case EAP_PEAPGTC:
						GetPEAPGTCCred(&config, user, pw, NULL, cacert);
					break;
					default:
					// noop
					break;
				}

				if (strlen(user))
					ns(Profile_security1_create_str(B, "1"));

				if (strlen(pw))
					ns(Profile_security2_create_str(B, "1"));

				if (strlen(cacert) || strlen(pacfn))
					ns(Profile_security3_create_str(B, "1"));

				if (strlen(pacpw) || strlen(usercert))
					ns(Profile_security4_create_str(B, "1"));

				if (strlen(usercrtpw))
					ns(Profile_security5_create_str(B, "1"));
			}
			break;
	}

	ns(Profile_end_as_root(B));
	}
	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_del_profile(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(String_table_t) profile_name;
	int ret;

	//TODO we ought to do some assertion that the cmd_table is a string
	profile_name = ns(Command_cmd_pl(cmd));

	ret = DeleteConfig((char*) ns(String_value(profile_name)));
	
	build_handshake_ack(B, ret);

	return 0; // any error is already in ack/Nack
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_get_profile_list(flatcc_builder_t *B, pthread_mutex_t *sdk_lock)
{
	SDCConfig *cfgs = NULL;
	unsigned long count = 0;
	int i, ret = SDCERR_SUCCESS;
	char currentcfgname[CONFIG_NAME_SZ];

	cfgs=malloc(MAX_CFGS*sizeof(SDCConfig));
	if (cfgs==NULL)
		return SDCERR_INSUFFICIENT_MEMORY;

	ret = GetAllConfigs(cfgs, &count);
	if (ret)
		return ret;

	ret = GetCurrentConfig(NULL, currentcfgname);
	if (ret) {
		DBGERROR("GetCurrentConfig() returned %d\n", ret);
		return ret;
	}

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Profile_list_type_identifier));
	ns(Profile_list_start(B));
	ns(Profile_list_profiles_start(B));

	for (i=0; i<count; i++) {
		unsigned char apStatus;
		unsigned char active;
		LRD_WF_AutoProfileCfgStatus(cfgs[i].configName, &apStatus);
		active = !strncmp(currentcfgname, cfgs[i].configName, CONFIG_NAME_SZ);

		ns(Profile_list_profiles_push_start(B));
		ns(P_entry_name_create_str(B, cfgs[i].configName));
		ns(P_entry_active_add(B, active));
		ns(P_entry_autoprof_add(B, apStatus));
		ns(Profile_list_profiles_push_end(B));

	}
	ns(Profile_list_profiles_end(B));
	ns(Profile_list_end_as_root(B));

	return ret;
}

#define LRD_WF_BSSID_LIST_ALLOC(numEntries) (sizeof(unsigned long) \
                          + ((numEntries) * sizeof(LRD_WF_SCAN_ITEM_INFO)))

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_get_scanlist (flatcc_builder_t *B, pthread_mutex_t *sdk_lock)
{
	unsigned long count = 0;
	static int initial_num_entries = 250;
	int i, num_entries, ret = SDCERR_SUCCESS;
	int again = 1;
	CF10G_STATUS status;
	LRD_WF_BSSID_LIST *list;
	LRD_WF_SCAN_ITEM_INFO *bss;

	ret = GetCurrentStatus(&status);
	if (ret)
		return ret;

	if (status.cardState==CARDSTATE_DISABLED)
		return DCAL_RADIO_DISABLED;

	list=(LRD_WF_BSSID_LIST*)malloc(LRD_WF_BSSID_LIST_ALLOC(initial_num_entries));
	if (list==NULL)
		return SDCERR_INSUFFICIENT_MEMORY;

	memset(list, 0, LRD_WF_BSSID_LIST_ALLOC(initial_num_entries));

	do {
		num_entries = initial_num_entries;
		ret = LRD_WF_GetBSSIDList(list, &num_entries);

		if (ret==SDCERR_INSUFFICIENT_MEMORY) {
			if (num_entries==-1)
				goto cleanup;

			initial_num_entries = num_entries * 1.25;  // 125% of request
			                                           // Keep it in static var
			                                           // for next time
			DBGINFO("increased scan elements to %d\n", initial_num_entries);
			safe_free(list);
			continue;
		}
	} while (again--);

	if (ret) goto cleanup;

	DBGINFO("Scan items: %lu\n", list->NumberOfItems);

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Scan_list_type_identifier));
	ns(Scan_list_start(B));
	ns(Scan_list_items_start(B));

	for (i=0; i<list->NumberOfItems; i++) {
		bss = &list->Bssid[i];
		DBGINFO("%d: %s on channel %d\n", i, bss->ssid.val, bss->channel);
		ns(Scan_list_items_push_start(B));
		ns(Scan_item_channel_add(B, bss->channel));
		ns(Scan_item_rssi_add(B, bss->rssi));
		ns(Scan_item_securityMask_add(B, bss->securityMask));
		ns(Scan_item_bss_add(B, bss->bssType));
		ns(Scan_item_mac_create(B, bss->bssidMac, MAC_SZ));
		ns(Scan_item_ssid_create(B, bss->ssid.val, bss->ssid.len));
		ns(Scan_list_items_push_end(B));

	}
	ns(Scan_list_items_end(B));
	ns(Scan_list_end_as_root(B));

cleanup:
	safe_free(list);

	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_activate_profile(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(String_table_t) string;
	int ret;
	string = ns(Command_cmd_pl(cmd));

	SDKLOCK(sdk_lock);
	ret = ActivateConfig((char*)ns(String_value(string)));
	SDKUNLOCK(sdk_lock);
	build_handshake_ack(B, ret);

	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_issue_radiorestart(flatcc_builder_t *B, pthread_mutex_t * sdk_lock)
{
	int ret;
	ret = system("ifrc wlan0 restart");
	build_handshake_ack(B, ret);
	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
SDCERR setIgnoreNullSsid(unsigned long value);
SDCERR getIgnoreNullSsid(unsigned long *value);
int do_get_globals(flatcc_builder_t *B, pthread_mutex_t *sdk_lock)
{
	SDCGlobalConfig gcfg = {0};
	int ret;
	unsigned long ignoreNullSSID = 0;
	unsigned char apStatus = 0;

	ret = GetGlobalSettings(&gcfg);

	if (ret)
		build_handshake_ack(B, ret);
	else
	{
		flatcc_builder_reset(B);
		flatbuffers_buffer_start(B, ns(Globals_type_identifier));
		ns(Globals_start(B));

		SDKLOCK(sdk_lock);
		getIgnoreNullSsid(&ignoreNullSSID);
		LRD_WF_AutoProfileStatus(&apStatus);
		SDKUNLOCK(sdk_lock);

		ns(Globals_auth_add(B, gcfg.authServerType));
		ns(Globals_channel_set_a_add(B, gcfg.aLRS));
		ns(Globals_channel_set_b_add(B, gcfg.bLRS));
		ns(Globals_auto_profile_add(B, apStatus));
		ns(Globals_beacon_miss_add(B, gcfg.BeaconMissTimeout));

		if (gcfg.CCXfeatures == CCX_OFF)
			ns(Globals_ccx_add(B, 0));
		else
			ns(Globals_ccx_add(B, 1));

		ns(Globals_cert_path_create_str(B, gcfg.certPath));
		ns(Globals_date_check_add(B,(gcfg.suppInfo & SUPPINFO_TLS_TIME_CHECK)));
		ns(Globals_def_adhoc_add(B, gcfg.defAdhocChannel));
		ns(Globals_fips_add(B, (gcfg.suppInfo & SUPPINFO_FIPS)));
		ns(Globals_pmk_add(B, gcfg.PMKcaching));
		ns(Globals_probe_delay_add(B, gcfg.probeDelay));
		ns(Globals_regdomain_add(B, gcfg.regDomain));
		ns(Globals_roam_periodms_add(B, gcfg.roamPeriodms));
		ns(Globals_roam_trigger_add(B, gcfg.roamTrigger));
		ns(Globals_rts_add(B, gcfg.RTSThreshold));
		ns(Globals_scan_dfs_add(B, gcfg.scanDFSTime));
		ns(Globals_ttls_add(B, gcfg.TTLSInnerMethod));
		ns(Globals_uapsd_add(B, gcfg.uAPSD));
		ns(Globals_wmm_add(B, gcfg.WMEenabled));
		ns(Globals_ignore_null_ssid_add(B, ignoreNullSSID));
		ns(Globals_dfs_channels_add(B, gcfg.DFSchannels));

		ns(Globals_end_as_root(B));
	}
	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_set_globals(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(Globals_table_t) gt;
	SDCGlobalConfig gcfg = {0};
	int ret;

	SDKLOCK(sdk_lock);
	GetGlobalSettings(&gcfg); // not all values are settable via the host
	                          // ie - some values are not supported on the
	                          // current hardware. Pull the current settings
	                          // so any values that are not set from this
	                          // call remain the same (and remain valid)

	//TODO we ought to do some assertion that the cmd_table is a globals
	gt = ns(Command_cmd_pl(cmd));

	gcfg.authServerType = ns(Globals_auth(gt));
	gcfg.aLRS = ns(Globals_channel_set_a(gt));
	gcfg.bLRS = ns(Globals_channel_set_b(gt));

	if (ns(Globals_auto_profile(gt)))
		gcfg.autoProfile |= 1;
	else
		gcfg.autoProfile &= ~1;

	gcfg.BeaconMissTimeout = ns(Globals_beacon_miss(gt));

	if (ns(Globals_ccx(gt)))
		gcfg.CCXfeatures = CCX_FULL;
	else
		gcfg.CCXfeatures = CCX_OFF;

	strncpy(gcfg.certPath, ns(Globals_cert_path(gt)), MAX_CERT_PATH - 1);
	if(ns(Globals_date_check(gt)))
		gcfg.suppInfo |= SUPPINFO_TLS_TIME_CHECK;
	else
		gcfg.suppInfo &= ~SUPPINFO_TLS_TIME_CHECK;
	gcfg.defAdhocChannel = ns(Globals_def_adhoc(gt));
	if (ns(Globals_fips(gt)))
		gcfg.suppInfo |= SUPPINFO_FIPS;
	else
		gcfg.suppInfo &= ~SUPPINFO_FIPS;
	gcfg.PMKcaching = ns(Globals_pmk(gt));
	gcfg.probeDelay = ns(Globals_probe_delay(gt));
	gcfg.regDomain = ns(Globals_regdomain(gt));
	gcfg.roamPeriodms = ns(Globals_roam_periodms(gt));
	gcfg.roamTrigger = ns(Globals_roam_trigger(gt));
	gcfg.RTSThreshold = ns(Globals_rts(gt));
	gcfg.scanDFSTime = ns(Globals_scan_dfs(gt));
	gcfg.TTLSInnerMethod = ns(Globals_ttls(gt));
	gcfg.uAPSD = ns(Globals_uapsd(gt));
	gcfg.WMEenabled = ns(Globals_wmm(gt));
	gcfg.DFSchannels = ns(Globals_dfs_channels(gt));

	setIgnoreNullSsid((unsigned long) ns(Globals_ignore_null_ssid(gt)));

	ret = SetGlobalSettings(&gcfg);
	if(ret) DBGERROR("SetGlobalsettings() returned %d at line %d\n", ret, __LINE__);
	else
		DBGINFO("SetGlobalSettings() returned success\n");

	SDKUNLOCK(sdk_lock);

	build_handshake_ack(B, ret);
	return 0;
}

int do_get_interface(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(String_table_t) interface_name;
	int ret = SDCERR_SUCCESS;

	//TODO we ought to do some assertion that the cmd_table is a string
	interface_name = ns(Command_cmd_pl(cmd));

	if (ret)
		build_handshake_ack(B, ret);
	else
	{
		int auto_start = -1;
		char method[STR_SZ];
		char address[STR_SZ];
		char netmask[STR_SZ];
		char gateway[STR_SZ];
		char broadcast[STR_SZ];
		char nameserver[STR_SZ];
		char bridge_ports[STR_SZ];
		int ap_mode = -1;
		int nat = -1;
		char method6[STR_SZ];
		char dhcp6[STR_SZ];
		char address6[IP6_STR_SZ];
		char netmask6[IP6_STR_SZ];
		char gateway6[IP6_STR_SZ];
		char nameserver6[IP6_STR_SZ];
		int nat6 = -1;

		flatcc_builder_reset(B);
		flatbuffers_buffer_start(B, ns(Interface_type_identifier));
		ns(Profile_start(B));

		ns(Interface_bridge_add(B, 0));
		ns(Interface_ap_mode_add(B, 0));

// Need to determine if the interface exists and return error if not.
// Elements of an interface that are not present are not errors and should
// not generate nacks.
// LRD_ENI_GetAutoStart() can be used to determine if an interface is
// present so do that call first.

		SDKLOCK(sdk_lock);
		ret = LRD_ENI_GetAutoStart((char*)ns(String_value(interface_name)), &auto_start);
		SDKUNLOCK(sdk_lock);
		if (ret==SDCERR_INVALID_CONFIG) {
			DBGINFO("%s: interface ->%s<- does not exist\n",__func__, ns(String_value(interface_name)));
			return ret; // process_buffer() builds nack with non-zero return
		}

		SDKLOCK(sdk_lock);
		//IPv4
		ret = LRD_ENI_GetMethod((char*)ns(String_value(interface_name)), method, sizeof(method));
		SDKUNLOCK(sdk_lock);
		//invalid config means no ipv4. (we already checked that interface exists)
		if(ret == SDCERR_INVALID_CONFIG){
			DBGINFO("%s IPv4 not found\n",ns(String_value(interface_name)));
			// This is not an error as there should be ipv6 data
		} else if (ret == SDCERR_INVALID_PARAMETER){
			DBGERROR("LRD_ENI_GetMethod returned %d near line %d\n",ret,__LINE__);
			return ret; // process_buffer() builds nack with non-zero return
		} else if (ret == SDCERR_SUCCESS){
			// we have ipv4 data
			ns(Interface_ipv4_add(B, 1));

			SDKLOCK(sdk_lock);
			ret = LRD_ENI_GetInterfacePropertyValue((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_ADDRESS, address, sizeof(address));
			if (ret != SDCERR_SUCCESS){
				address[0] = '\0';
				DBGDEBUG("%s IPv4 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_ADDRESS);
			}

			ret = LRD_ENI_GetInterfacePropertyValue((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_NETMASK, netmask, sizeof(netmask));
			if (ret != SDCERR_SUCCESS){
				netmask[0] = '\0';
				DBGDEBUG("%s IPv4 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_NETMASK);
			}

			ret = LRD_ENI_GetInterfacePropertyValue((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_GATEWAY, gateway, sizeof(gateway));
			if (ret != SDCERR_SUCCESS){
				gateway[0] = '\0';
				DBGDEBUG("%s IPv4 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_GATEWAY);
			}

			ret = LRD_ENI_GetInterfacePropertyValue((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_BROADCAST, broadcast, sizeof(broadcast));
			if (ret != SDCERR_SUCCESS){
				broadcast[0] = '\0';
				DBGDEBUG("%s IPv4 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_BROADCAST);
			}

			ret = LRD_ENI_GetInterfacePropertyValue((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_NAMESERVER, nameserver, sizeof(nameserver));
			if (ret != SDCERR_SUCCESS){
				nameserver[0] = '\0';
				DBGDEBUG("%s IPv4 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_NAMESERVER);
			}

			ret = LRD_ENI_GetInterfacePropertyValue((char*)LRD_ENI_INTERFACE_BRIDGE, (char*) LRD_ENI_PROPERTY_BRIDGEPORTS, bridge_ports, sizeof(bridge_ports));
			if (ret != SDCERR_SUCCESS){
				bridge_ports[0] = '\0';
				DBGDEBUG("%s is not configured for bridging\n",ns(String_value(interface_name)));
			} else {
				if (strstr(bridge_ports,(char*)ns(String_value(interface_name))) != NULL){
					char method_bridge[STR_SZ];
					ret = LRD_ENI_GetMethod((char*)LRD_ENI_INTERFACE_BRIDGE, method_bridge, sizeof(method_bridge));
					if (ret == SDCERR_SUCCESS){
						ns(Interface_bridge_add(B, 1));
					}
				}
			}

			ret = LRD_ENI_GetHostAPD((char*)ns(String_value(interface_name)), &ap_mode);
			if (ret == SDCERR_SUCCESS){
				if (!ap_mode)
					DBGDEBUG("%s AP mode not set\n",ns(String_value(interface_name)));
			} else {
				DBGERROR("%s failed to retrieve AP mode information\n",ns(String_value(interface_name)));
				SDKUNLOCK(sdk_lock);
				return ret; // process_buffer() builds nack with non-zero return
			}

			ret = LRD_ENI_GetNat((char*)ns(String_value(interface_name)), &nat);
			SDKUNLOCK(sdk_lock);
			if (ret == SDCERR_SUCCESS){
				if (!nat)
					DBGDEBUG("%s IPv4 NAT is not set\n",ns(String_value(interface_name)));
			} else {
				DBGERROR("%s failed to retrieve IPv4 NAT information\n",ns(String_value(interface_name)));
				return ret; // process_buffer() builds nack with non-zero return
			}
		}
		//IPv6
		SDKLOCK(sdk_lock);
		ret = LRD_ENI_GetMethod6((char*)ns(String_value(interface_name)), method6, sizeof(method6));
		SDKUNLOCK(sdk_lock);
		if(ret == SDCERR_INVALID_CONFIG){
			DBGERROR("%s IPv6 not found\n",ns(String_value(interface_name)));
			// This is not an error as there should be ipv4 data
		} else if (ret == SDCERR_INVALID_PARAMETER){
			DBGERROR("LRD_ENI_GetMethod returned %d at line %d\n",ret,__LINE__);
			return ret; // process_buffer() builds nack with non-zero return
		} else if (ret == SDCERR_SUCCESS){
			ns(Interface_ipv6_add(B, 1));
			SDKLOCK(sdk_lock);
			ret = LRD_ENI_GetInterfacePropertyValue6((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_DHCP, dhcp6, sizeof(dhcp6));
			if (ret != SDCERR_SUCCESS){
				dhcp6[0] = '\0';
				DBGDEBUG("%s IPv6 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_DHCP);
			}

			ret = LRD_ENI_GetInterfacePropertyValue6((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_ADDRESS, address6, sizeof(address6));
			if (ret != SDCERR_SUCCESS){
				address6[0] = '\0';
				DBGDEBUG("%s IPv6 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_ADDRESS);
			}

			ret = LRD_ENI_GetInterfacePropertyValue6((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_NETMASK, netmask6, sizeof(netmask6));
			if (ret != SDCERR_SUCCESS){
				netmask6[0] = '\0';
				DBGDEBUG("%s IPv6 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_NETMASK);
			}

			ret = LRD_ENI_GetInterfacePropertyValue6((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_GATEWAY, gateway6, sizeof(gateway6));
			if (ret != SDCERR_SUCCESS){
				gateway6[0] = '\0';
				DBGDEBUG("%s IPv6 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_GATEWAY);
			}

			ret = LRD_ENI_GetInterfacePropertyValue6((char*)ns(String_value(interface_name)), (char*) LRD_ENI_PROPERTY_NAMESERVER, nameserver6, sizeof(nameserver6));
			if (ret != SDCERR_SUCCESS){
				nameserver6[0] = '\0';
				DBGDEBUG("%s IPv6 property %s not found\n",ns(String_value(interface_name)),LRD_ENI_PROPERTY_NAMESERVER);
			}

			ret = LRD_ENI_GetNat6((char*)ns(String_value(interface_name)), &nat6);
			if (ret == SDCERR_SUCCESS){
				if (!nat)
					DBGDEBUG("%s IPv6 NAT is not set\n",ns(String_value(interface_name)));
			} else {
				DBGERROR("%s failed to retrieve IPv6 NAT information\n",ns(String_value(interface_name)));
				SDKUNLOCK(sdk_lock);
				return ret; // process_buffer() builds nack with non-zero return
			}
			SDKUNLOCK(sdk_lock);
		}

		ns(Interface_interface_name_create_str(B, ns(String_value(interface_name))));
		ns(Interface_auto_start_add(B, auto_start));
		ns(Interface_method_create_str(B, method));
		ns(Interface_address_create_str(B, address));
		ns(Interface_netmask_create_str(B, netmask));
		ns(Interface_gateway_create_str(B, gateway));
		ns(Interface_broadcast_create_str(B, broadcast));
		ns(Interface_nameserver_create_str(B, nameserver));
		ns(Interface_ap_mode_add(B, ap_mode));
		ns(Interface_nat_add(B, nat));
		ns(Interface_method6_create_str(B, method6));
		ns(Interface_dhcp6_create_str(B, dhcp6));
		ns(Interface_address6_create_str(B, address6));
		ns(Interface_netmask6_create_str(B, netmask6));
		ns(Interface_gateway6_create_str(B, gateway6));
		ns(Interface_nameserver6_create_str(B, nameserver6));
		ns(Interface_nat6_add(B, nat6));

		ns(Interface_end_as_root(B));
	}
	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_set_interface(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
#define INTERFACE_DISABLE 1
#define INTERFACE_ENABLE  2
#define CLEAR_PROP_BITMASK_SWITCH(x) \
                          for (uint64_t bit = 1; (x) >= bit; bit *= 2) if ((x) & bit) switch (bit)


	ns(Interface_table_t) interface;
	int ret = SDCERR_FAIL;

	//TODO we ought to do some assertion that the cmd_table is a interface
	interface = ns(Command_cmd_pl(cmd));

	if (flatbuffers_string_len(ns(Interface_interface_name(interface)))){
		//IPv4
		if (ns(Interface_ipv4(interface))){
			SDKLOCK(sdk_lock);
			ret = LRD_ENI_AddInterface((char*)ns(Interface_interface_name(interface)));
			SDKUNLOCK(sdk_lock);
			if(ret){
				return ret;
			}
			if (flatbuffers_string_len(ns(Interface_method(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetMethod((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_method(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetMethod() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_address(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetAddress((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_address(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetAddress() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_netmask(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetNetmask((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_netmask(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetNetmask() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_gateway(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetGateway((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_gateway(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetGateway() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_nameserver(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetNameserver((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_nameserver(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetNameserver() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_broadcast(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetBroadcastAddress((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_broadcast(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetBroadcastAddress() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (ns(Interface_state(interface))){
				if (ns(Interface_state(interface)) == INTERFACE_ENABLE){
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_EnableInterface((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_EnableInterface() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
				else{
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_DisableInterface((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_DisableInterface() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
			}
			if (ns(Interface_bridge(interface))){
				if (ns(Interface_bridge(interface)) == INTERFACE_ENABLE){
					char bridge_ports[STR_SZ];
					sprintf(bridge_ports, "%s %s", (char*)ns(Interface_interface_name(interface)), LRD_ENI_INTERFACE_WIFI);
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_SetBridgePorts(LRD_ENI_INTERFACE_BRIDGE,bridge_ports);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_SetBridgePorts() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
				else{
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_BRIDGEPORTS);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
			}
			if (ns(Interface_ap_mode(interface))){
				if (ns(Interface_ap_mode(interface)) == INTERFACE_ENABLE){
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_EnableHostAPD((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_EnableHostAPD() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
				else{
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_DisableHostAPD((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_DisableHostAPD() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
			}
			if (ns(Interface_nat(interface))){
				if (ns(Interface_nat(interface)) == INTERFACE_ENABLE){
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_EnableNat((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_EnableNat() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
				else{
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_DisableNat((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_DisableNat() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
			}
		}
		//IPv6
		if (ns(Interface_ipv6(interface))){
			SDKLOCK(sdk_lock);
			ret = LRD_ENI_AddInterface6((char*)ns(Interface_interface_name(interface)));
			SDKUNLOCK(sdk_lock);
			if(ret){
				DBGERROR("LRD_ENI_AddInterface6() returned %d at line %d\n", ret, __LINE__);
				return ret;
			}
			if (flatbuffers_string_len(ns(Interface_method6(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetMethod6((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_method6(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetMethod6() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_dhcp6(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetDhcp6((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_dhcp6(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetDhcp6() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_address6(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetAddress6((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_address6(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetAddress6() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_netmask6(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetNetmask6((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_netmask6(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetNetmask6() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_gateway6(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetGateway6((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_gateway6(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetGateway6() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (flatbuffers_string_len(ns(Interface_nameserver6(interface)))){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_SetNameserver6((char*)ns(Interface_interface_name(interface)),(char*)ns(Interface_nameserver6(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_SetNameserver6() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			if (ns(Interface_state6(interface))){
				if (ns(Interface_state6(interface)) == INTERFACE_ENABLE){
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_EnableInterface6((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_EnableInterface6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
				else{
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_DisableInterface6((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_DisableInterface6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
			}
			if (ns(Interface_nat6(interface))){
				if (ns(Interface_nat6(interface)) == INTERFACE_ENABLE){
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_EnableNat6((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_EnableNat6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
				else{
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_DisableNat6((char*)ns(Interface_interface_name(interface)));
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_DisableNat6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
				}
			}
		}
		if (ns(Interface_auto_start(interface))){
			if (ns(Interface_auto_start(interface)) == INTERFACE_ENABLE){
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_AutoStartOn((char*)ns(Interface_interface_name(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_AutoStartOn() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
			else{
				SDKLOCK(sdk_lock);
				ret = LRD_ENI_AutoStartOff((char*)ns(Interface_interface_name(interface)));
				SDKUNLOCK(sdk_lock);
				if(ret){
					DBGERROR("LRD_ENI_AutoStartOff() returned %d at line %d\n", ret, __LINE__);
					return ret;
				}
			}
		}
		//Clear IPv4 properties
		if (ns(Interface_prop(interface))){
			CLEAR_PROP_BITMASK_SWITCH(ns(Interface_prop(interface)))
			{
				case ADDRESS:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_ADDRESS);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case NETMASK:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_NETMASK);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case GATEWAY:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_GATEWAY);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case BROADCAST:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_BROADCAST);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case NAMESERVER:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_NAMESERVER);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				default:
					DBGERROR("Unknown option passed to LRD_ENI_ClearProperty() at line %d\n", __LINE__);
					break;
			}
		}
		//Clear IPv6 properties
		if (ns(Interface_prop6(interface))){
			CLEAR_PROP_BITMASK_SWITCH(ns(Interface_prop6(interface)))
			{
				case ADDRESS:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty6((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_ADDRESS);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case NETMASK:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty6((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_NETMASK);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case GATEWAY:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty6((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_GATEWAY);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case NAMESERVER:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty6((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_NAMESERVER);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				case DHCP:
					SDKLOCK(sdk_lock);
					ret = LRD_ENI_ClearProperty6((char*)ns(Interface_interface_name(interface)),LRD_ENI_PROPERTY_DHCP);
					SDKUNLOCK(sdk_lock);
					if(ret){
						DBGERROR("LRD_ENI_ClearProperty6() returned %d at line %d\n", ret, __LINE__);
						return ret;
					}
					break;
				default:
					DBGERROR("Unknown option passed to LRD_ENI_ClearProperty6() at line %d\n", __LINE__);
					break;
			}
		}
	} else {
		DBGERROR("Invalid name: ->%s<-\n", (char*)ns(Interface_interface_name(interface)));
		ret = SDCERR_INVALID_NAME;
	}

	build_handshake_ack(B, ret);
	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_del_interface(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(String_table_t) interface_name;
	int ret;

	//TODO we ought to do some assertion that the cmd_table is a string
	interface_name = ns(Command_cmd_pl(cmd));

	SDKLOCK(sdk_lock);
	ret = LRD_ENI_RemoveInterface((char*) ns(String_value(interface_name)));
	SDKUNLOCK(sdk_lock);
	if(ret) DBGERROR("LRD_ENI_RemoveInterface() returned %d at line %d\n", ret, __LINE__);
	else {
		SDKLOCK(sdk_lock);
		ret = LRD_ENI_RemoveInterface6((char*) ns(String_value(interface_name)));
		SDKUNLOCK(sdk_lock);
		if(ret) DBGERROR("LRD_ENI_RemoveInterface6() returned %d at line %d\n", ret, __LINE__);
	}

	build_handshake_ack(B, ret);

	return 0; // any error is already in ack/Nack
}

int do_get_lease(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	int ret = SDCERR_FAIL;
	ns(String_table_t) interface_name;
	DHCP_LEASE DHCPLease;

	//TODO we ought to do some assertion that the cmd_table is a string
	interface_name = ns(Command_cmd_pl(cmd));

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Lease_type_identifier));
	ns(Lease_start(B));

	SDKLOCK(sdk_lock);
	ret = LRD_WF_GetDHCPIPv4Lease(&DHCPLease, (char*) ns(String_value(interface_name)));
	SDKUNLOCK(sdk_lock);

	if(ret){
		DBGERROR("LRD_WF_GetDHCPIPv4Lease() returned %d at line %d\n", ret, __LINE__);
		build_handshake_ack(B, ret);
		return ret;
	}

	ns(Lease_interface_create_str(B, DHCPLease.interface));
	ns(Lease_address_create_str(B, DHCPLease.address));
	ns(Lease_subnet_mask_create_str(B, DHCPLease.subnet_mask));
	ns(Lease_routers_create_str(B, DHCPLease.routers));
	ns(Lease_lease_time_add(B, DHCPLease.lease_time));
	ns(Lease_message_type_add(B, DHCPLease.message_type));
	ns(Lease_dns_servers_create_str(B, DHCPLease.dns_servers));
	ns(Lease_dhcp_server_create_str(B, DHCPLease.dhcp_server));
	ns(Lease_domain_name_create_str(B, DHCPLease.domain_name));
	ns(Lease_renew_create_str(B, DHCPLease.renew));
	ns(Lease_rebind_create_str(B, DHCPLease.rebind));
	ns(Lease_expire_create_str(B, DHCPLease.expire));

	ns(Lease_end_as_root(B));

	return 0;
}

int do_get_default_route(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	int ret = SDCERR_FAIL;
	ns(String_table_t) interface_name;
	DEFAULT_ROUTE default_route;

	interface_name = ns(Command_cmd_pl(cmd));

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Default_route_type_identifier));
	ns(Default_route_start(B));

	SDKLOCK(sdk_lock);
	ret = LRD_WF_GetDefaultRoute(&default_route, (char *)LRD_ROUTE_FILE, (char*) ns(String_value(interface_name)));
	SDKUNLOCK(sdk_lock);

	if(ret){
		DBGERROR("LRD_WF_GetDefaultRoute() returned %d at line %d\n", ret, __LINE__);
		build_handshake_ack(B, ret);
		return ret;
	}

	ns(Default_route_interface_create_str(B, default_route.interface));
	ns(Default_route_destination_create_str(B, default_route.destination));
	ns(Default_route_gateway_create_str(B, default_route.gateway));
	ns(Default_route_flags_add(B, default_route.flags));
	ns(Default_route_metric_add(B, default_route.metric));
	ns(Default_route_subnet_mask_create_str(B, default_route.subnet_mask));
	ns(Default_route_mtu_add(B, default_route.mtu));
	ns(Default_route_window_add(B, default_route.window));
	ns(Default_route_irtt_add(B, default_route.irtt));

	ns(Default_route_end_as_root(B));

	return 0;
}

int do_system_command(flatcc_builder_t *B, char *commandline)
{
	int ret = DCAL_SUCCESS;
	FILE *file = NULL;

	if (commandline==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else
	{
		DBGDEBUG("Issuing: '%s'\n", commandline);

		file = popen(commandline, "w");
		if (file==NULL) {
			DBGDEBUG("popen error\n");
			ret = DCAL_WB_GENERAL_FAIL;
		} else {
			ret = pclose(file);
			if (ret == -1) {
				DBGDEBUG("pclose error\n");
				ret = DCAL_WB_GENERAL_FAIL;
			}
			else
				ret =(WEXITSTATUS(ret)?DCAL_REMOTE_SHELL_CMD_FAILURE:DCAL_SUCCESS);
		}
	}

	DBGERROR("Command return code: %d\n", ret);

	build_handshake_ack(B, ret);
	return 0;
}

// return 0 on success; 1 on failure
int in_valid_set(char c)
{

	if ((c >= 'a') && (c <='z')) //lower case alpha
		return 0;

	if ((c >= 'A') && (c <='Z')) //upper case alpha
		return 0;

	if ((c >= '-') && (c <='9')) //'-','.','/',digits
		return 0;

	if (c=='_')
		return 0;

	return 1;
}

int validate_fqdn(char *str)
{
	int i, len;

	if (str==NULL)
		return 0;

	len = strlen(str);

	for (i=0; i<len; i++)
		if (in_valid_set(str[i])==1)
			return 1;

	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_issue_ntpdate(flatcc_builder_t *B, ns(Command_table_t) ct)
{
	ns(String_table_t) string;
	char *commandline = NULL;
	int ret;

	string = ns(Command_cmd_pl(ct));

	if (((char*)ns(String_value(string)))==NULL)
		return DCAL_INVALID_PARAMETER;

	if(validate_fqdn(((char*)ns(String_value(string))))==1)
		return DCAL_FQDN_FAILURE;

#define NTPDATE "/usr/bin/ntpdate "
	commandline = (char*)malloc(strlen(NTPDATE)+
		                    strlen((char*)ns(String_value(string)))+2);
	if (commandline==NULL)
		return DCAL_WB_INSUFFICIENT_MEMORY;

	sprintf(commandline, "%s%s", NTPDATE, (char*)ns(String_value(string)));

	ret = do_system_command(B, commandline);
	free(commandline);

	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_get_time(flatcc_builder_t *B)
{
	struct timeval tv;

	if (!gettimeofday(&tv, NULL))
	{
		flatcc_builder_reset(B);
		flatbuffers_buffer_start(B, ns(Time_type_identifier));
		ns(Time_start(B));
		ns(Time_tv_sec_add(B, tv.tv_sec));
		ns(Time_tv_usec_add(B, tv.tv_usec));

		ns(Time_end_as_root(B));
	} else {
		DBGERROR("gettimeofday() failed with %s\n",strerror(errno));
		build_handshake_ack(B, DCAL_WB_GENERAL_FAIL);
	}

	return 0;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_set_time(flatcc_builder_t *B, ns(Command_table_t) cmd)
{
	struct timeval tv;
	int ret = DCAL_SUCCESS;
	ns(Time_table_t) tt;

	tt = ns(Command_cmd_pl(cmd));

	tv.tv_sec = ns(Time_tv_sec(tt));
	tv.tv_usec = ns(Time_tv_usec(tt));

	if (settimeofday(&tv, NULL)) {
		ret = DCAL_WB_GENERAL_FAIL;
		DBGERROR("settimeofday() failed with %s\n",strerror(errno));
		DBGERROR("called with (%d,%d)\n", ns(Time_tv_sec(tt)), ns(Time_tv_usec(tt)));
	}

	build_handshake_ack(B, ret);
	return 0;
}

static char *lrd_strdup(const char *src)
{
	if (src == NULL)
		return NULL;

	return strdup(src);
}

		//send start ack
int send_an_ack( flatcc_builder_t *B, char * buf, size_t bufsize, ssh_channel chan, int error)
{
	size_t nbytes;
	int w, ret = DCAL_SUCCESS;
	build_handshake_ack(B, error);
	flatcc_builder_copy_buffer(B, buf, bufsize);
	nbytes =flatcc_builder_get_buffer_size(B);

	if (nbytes <= 0) {
		flatcc_builder_clear(B);
		DBGERROR("an error unrecoverable error was sent to client from line %d\n", -nbytes);
		ret = DCAL_FLATBUFF_ERROR;
		build_handshake_ack(B, ret);
	}else {
		w = ssh_channel_write(chan, buf, nbytes);
		if (nbytes != w){
			DBGERROR("Failure to send buffer from %s\n", __func__);
			ret = -__LINE__;
		}
	}
	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_receive_file(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock, ssh_channel chan)
{
	ns(Filexfer_table_t) fxt;
	int ret = DCAL_SUCCESS;
	int fd;
	int size,mode,r,w,total=0;
	char *full_path=NULL;
	char *tmpfile=NULL;
	char *path= TMPDIR;
	char *filename=NULL;
	char *full_file_path = NULL;
	char *buf=NULL;
	SDCGlobalConfig gcfg = {0};
	struct stat st = {0};

	fxt = ns(Command_cmd_pl(cmd));
	if(flatbuffers_string_len(ns(Filexfer_file_path(fxt)))==0)
		return DCAL_INVALID_PARAMETER;
	else
	{
		size = ns(Filexfer_size(fxt));
		mode = ns(Filexfer_mode(fxt));
		full_path = lrd_strdup(ns(Filexfer_file_path(fxt)));

		if(!full_path) {
			ret = DCAL_NO_MEMORY;
			goto cleanup;
		}

		tmpfile = lrd_strdup(full_path);
		if(tmpfile)
			filename = lrd_strdup(basename(full_path));

		if(ns(Filexfer_cert(fxt))){
			ret = GetGlobalSettings(&gcfg);
			if (ret != SDCERR_SUCCESS){
				DBGERROR("GetGlobalSettings() returned %d at line %d\n", ret, __LINE__);
				goto cleanup;
			}

			path = gcfg.certPath;
		}

		if (stat(path, &st) == -1)
			if (mkdir(path, mode) != 0){
				ret = DCAL_WB_INVALID_FILE;
				DBGERROR("Unable to create directory at line %d\n", __LINE__);
				goto cleanup;
			}

		full_file_path = malloc(strlen(path)+strlen(filename)+2);
		buf = malloc(FILEBUFSZ);
		if ((!full_file_path)||!(buf)) {
			ret = DCAL_NO_MEMORY;
			goto cleanup;
		}
		memset(buf, 0, FILEBUFSZ);
		sprintf(full_file_path,"%s/%s",path,filename);
		DBGINFO("incoming file to be saved to: %s\n",full_file_path);

		fd = open(full_file_path, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			ret = DCAL_REMOTE_FILE_ACCESS_DENIED;
			goto cleanup;
		}

		ret=send_an_ack(B, buf, FILEBUFSZ, chan, ret);
		if (ret)
			goto closefile;

		// read the file from socket, write to fs
		memset(buf, 0, FILEBUFSZ);  //TODO is there any security benefit for this clear, or if placed inside the loop to be cleared before each channel_read?
		do {
			r = ssh_channel_read(chan, buf, FILEBUFSZ, 0);
			if(r==SSH_ERROR){
				DBGERROR("Failure to read ssh buffer\n");
				ret =-__LINE__;
				goto closefile;
			} else if (r==0)
				break;
			w = write(fd, buf, r);
			if (w != r) {
				DBGERROR("error writing local file: %s\n", full_path);
				ret = DCAL_REMOTE_FILE_ACCESS_DENIED;
				goto closefile;
			}
			total += r;
		} while (total < size);

		if(fsync(fd) < 0)
		{
			DBGERROR("error syncing data to local file: %s\n", full_path);
			ret = DCAL_REMOTE_FILE_ACCESS_DENIED;
			goto closefile;
		}
		DBGINFO("Wrote %d bytes to fs\n", total);
		build_handshake_ack(B, ret);
	}
closefile:
	close(fd);
	if (!ret)
		chmod(full_path, mode);

cleanup:
	safe_free(buf);
	safe_free(full_path);
	safe_free(tmpfile);
	// do not free path as it pointing to a static string
	safe_free(filename);
	safe_free(full_file_path);

	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_send_file(flatcc_builder_t *B, ns(Command_table_t) cmd, char *filename, pthread_mutex_t *sdk_lock, ssh_channel chan)
{
	char *buf = NULL, *localfilename = NULL;
	ns(String_table_t) string;
	ns(Filexfer_table_t) fxt;
	ns(Cmd_pl_union_ref_t) cmd_pl;
	struct stat stats;
	int fd, r, w, ret = DCAL_SUCCESS;
	size_t total, size;
	FILE *file=NULL;

	string = ns(Command_cmd_pl(cmd));
	size = flatbuffers_string_len(ns(String_value(string)));
	if(size==0) {
		if (filename==NULL) {
			ret = DCAL_INVALID_PARAMETER; // one of cmd and filename must have a value
		} else {
			// the filename parameter allows the dcas internals to specify a
			// file outside of the /tmp directory
			localfilename = lrd_strdup(filename);
		}
	} else {//extract filename from Command_Table
		char *tmp = lrd_strdup(ns(String_value(string)));
		char *bname = lrd_strdup(basename(tmp));
		localfilename = malloc(sizeof(TMPDIR)+strlen(bname)+2);
		if (localfilename){
			sprintf(localfilename,"%s/%s",TMPDIR,bname);
		}
		safe_free (tmp);
		safe_free (bname);
	}
	if (!localfilename)
		ret = DCAL_NO_MEMORY;
	else {
		buf = malloc(FILEBUFSZ);
		if (!buf)
			ret = DCAL_NO_MEMORY;
	}

	if (ret==DCAL_SUCCESS){
		DBGINFO("getting file: %s\n", localfilename);

		file = fopen(localfilename, "r");
		if (!file) {
			ret = DCAL_REMOTE_FILE_ACCESS_DENIED;
			goto cleanup;
		}

		fd = fileno(file);
		if(fd<0) {
			ret = DCAL_REMOTE_FILE_ACCESS_DENIED;
			goto cleanup;
		}

		size = fstat(fd, &stats);
		if (size<0){
			ret = DCAL_REMOTE_FILE_ACCESS_DENIED;
			goto cleanup;
		}

		flatcc_builder_reset(B);
		ns(Filexfer_start(B));
		ns(Filexfer_file_path_create_str(B, localfilename));
		ns(Filexfer_size_add(B,stats.st_size));
		ns(Filexfer_mode_add(B,stats.st_mode));
		cmd_pl = ns(Cmd_pl_as_Filexfer(ns(Filexfer_end(B))));

		flatbuffers_buffer_start(B, ns(Command_type_identifier));
		ns(Command_start(B));
		ns(Command_cmd_pl_add(B, cmd_pl));
		ns(Command_command_add(B, ns(Commands_FILEPUSH)));
		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<FILEBUFSZ);
		flatcc_builder_copy_buffer(B, buf, size);

		w = ssh_channel_write(chan, buf, size);
		if (size != w){
				DBGERROR("Failure to send buffer from %s\n", __func__);
				ret = -__LINE__;
				goto cleanup;
		}

		if (ret)
			goto cleanup;

		size = stats.st_size;
		total = 0;
		// now read the file from fs and write to socket
		memset(buf, 0, FILEBUFSZ);  //TODO is there any security benefit for this clear, or if placed inside the loop to be cleared before each fread?
		do {

			r = fread(buf, 1, FILEBUFSZ, file);
			if(r==0) break;
			else if (r<0){
				DBGERROR("Error reading file: %s\n", localfilename);
				ret = DCAL_REMOTE_FILE_ACCESS_DENIED;
				goto cleanup;
			}
			w = ssh_channel_write(chan, buf, r);
			if (w!=r){
				DBGERROR("Failure to send buffer from %s\n", __func__);
				DBGERROR("Bytes from from file: %d\n"
				         "Bytes written to chan: %d\n", r, w);
				ret = -__LINE__;
				goto cleanup;
			}

			total += r;

		} while (total < size);

		if (ret==DCAL_SUCCESS)
			DBGINFO("Wrote %d bytes to ssh channel\n", total);
		else
			DBGERROR("DCAL failure in %s: %d\n", __func__, ret);
		build_handshake_ack(B, ret);

	}

cleanup:
	if(file)
		fclose(file);
	safe_free(buf);
	safe_free(localfilename);
	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_fw_update(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(U32_table_t) u32;
	char *commandline = NULL;
	unsigned int flags, cmdlinelen = 0;
	int ret;

	u32 = ns(Command_cmd_pl(cmd));

#define FWUPDATE               "/usr/sbin/fw_update "
#define FWTXT                  " /tmp/fw.txt"
#define FWU_FORCE_F            " -f"
#define FWU_DISABLE_REBOOT_F   " -xr"
#define FWU_DISABLE_NOTIFY_F   "n"
#define FWU_DISABLE_TRANSFER_F "t"
#define DEBUGFILE " > /tmp/fw_update.out"

	cmdlinelen = strlen(FWUPDATE)+
	              strlen(FWTXT)+
	              strlen(FWU_DISABLE_REBOOT_F) + 1
	              + strlen(DEBUGFILE);

	flags = ns(U32_value(u32));

	if (flags & FWU_FORCE)
		cmdlinelen += strlen(FWU_FORCE_F);

	if (flags & FWU_DISABLE_NOTIFY)
		cmdlinelen += strlen(FWU_DISABLE_NOTIFY_F);

	if (flags & FWU_DISABLE_TRANSFER)
		cmdlinelen += strlen(FWU_DISABLE_TRANSFER_F);

	commandline = (char*)malloc(cmdlinelen);
	if (commandline==NULL)
		return DCAL_WB_INSUFFICIENT_MEMORY;

	sprintf(commandline, "%s%s%s%s%s%s%s",
	               FWUPDATE,
	               (flags & FWU_FORCE)?FWU_FORCE_F:"",
	               FWU_DISABLE_REBOOT_F,
	               (flags & FWU_DISABLE_NOTIFY)?FWU_DISABLE_NOTIFY_F:"",
	               (flags & FWU_DISABLE_TRANSFER)?FWU_DISABLE_TRANSFER_F:"",
	               FWTXT,
	               DEBUGFILE);

	ret = do_system_command(B, commandline);
	free(commandline);

	return ret;
}

int do_swupdate(flatcc_builder_t *B, ns(Command_table_t) cmd)
{
	char * commandline = NULL;
	ns(String_table_t) string;
	int ret = 0;
	struct stat buffer;

#define SWUPDATE "/usr/bin/swupdate"
	string = ns(Command_cmd_pl(cmd));

	if (((char*)ns(String_value(string)))==NULL)
		return DCAL_INVALID_PARAMETER;

	if (stat(SWUPDATE,&buffer))
		return DCAL_REMOTE_USER_CMD_NOT_EXIST;

	commandline = (char*)malloc(strlen(SWUPDATE)+
		                    strlen((char*)ns(String_value(string)))+2);
	if (commandline==NULL)
		return DCAL_WB_INSUFFICIENT_MEMORY;

	sprintf(commandline, "%s %s", SWUPDATE, (char*)ns(String_value(string)));
	ret = do_system_command(B, commandline);
	free(commandline);

	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_process_cli_file(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(String_table_t) string;
	char *commandline = NULL;
	char *tmppath = NULL;
	char *tmpname = NULL;
	char *filename = NULL;
	int ret;

	string = ns(Command_cmd_pl(cmd));

	if(flatbuffers_string_len(ns(String_value(string)))==0)
		return DCAL_INVALID_PARAMETER;

	tmppath=lrd_strdup(ns(String_value(string)));
	tmpname=lrd_strdup(basename(tmppath));

	filename=malloc(strlen(TMPDIR)+strlen(tmpname)+2);
	if(!filename) {
		ret = DCAL_WB_INSUFFICIENT_MEMORY;
		goto cleanup;
	}

	sprintf(filename, "%s/%s", TMPDIR, tmpname);

	if (access( filename, R_OK) == -1){
		ret = DCAL_WB_INSUFFICIENT_MEMORY;
		goto cleanup;
	}

#define SDCCLI "/usr/bin/sdc_cli < "
	commandline = (char*)malloc(strlen(SDCCLI)+
		                    strlen(filename)+2);
	if (commandline==NULL){
		ret = DCAL_WB_INSUFFICIENT_MEMORY;
		goto cleanup;
	}

	sprintf(commandline, "%s%s", SDCCLI, filename);

	ret = do_system_command(B, commandline);

	cleanup:
	safe_free(commandline);
	safe_free(tmppath);
	safe_free(tmpname);
	safe_free(filename);
	return ret;

}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_get_logs(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock, ssh_channel chan)
{
	char *commandline = NULL;
	int ret;

	commandline = "/usr/bin/log_dump";

//remove any pre-existing logfile
	remove("/tmp/log_dump.txt");

	ret = do_system_command(B, commandline);

	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int process_command(flatcc_builder_t *B, ns(Command_table_t) cmd,
 pthread_mutex_t *sdk_lock, bool *exit_called, ssh_channel chan)
{
	switch(ns(Command_command(cmd))){
		case ns(Commands_GETSTATUS):
			DBGDEBUG("Get Status\n");
			return build_status(B, sdk_lock);
			break;
		case ns(Commands_GETVERSIONS):
			DBGDEBUG("Get Version\n");
			return build_version(B, sdk_lock);
			break;
		case ns(Commands_WIFIENABLE):
		case ns(Commands_WIFIDISABLE):
			DBGDEBUG("%s\n",
			                ns(Command_command(cmd))==ns(Commands_WIFIENABLE)?
			                "enable":"disable");
			return do_enable_disable(B, sdk_lock,
			          ns(Command_command(cmd))==ns(Commands_WIFIENABLE));
			break;
		case ns(Commands_SETPROFILE):
			DBGDEBUG("set profile\n");
			return do_set_profile(B, cmd, sdk_lock);
			break;
		case ns(Commands_ACTIVATEPROFILE):
			DBGDEBUG("activate profile\n");
			return do_activate_profile(B, cmd, sdk_lock);
			break;
		case ns(Commands_WIFIRESTART):
			DBGDEBUG("wifi restart\n");
			return do_issue_radiorestart(B, sdk_lock);
			break;
		case ns(Commands_SYSTEMREBOOT):
			DBGDEBUG("system reboot\n");
			build_handshake_ack(B, 0);
			*exit_called = true;
			return 0;
			break;
		case ns(Commands_GETPROFILE):
			DBGDEBUG("Get profile\n");
			return do_get_profile(B, cmd, sdk_lock);
			break;
		case ns(Commands_DELPROFILE):
			DBGDEBUG("Del profile\n");
			return do_del_profile(B, cmd, sdk_lock);
			break;
		case ns(Commands_GETGLOBALS):
			DBGDEBUG("Get Globals\n");
			return do_get_globals(B, sdk_lock);
			break;
		case ns(Commands_SETGLOBALS):
			DBGDEBUG("Set Globals\n");
			return do_set_globals(B, cmd, sdk_lock);
			break;
		case ns(Commands_GETINTERFACE):
			DBGDEBUG("Get Interface\n");
			return do_get_interface(B, cmd, sdk_lock);
			break;
		case ns(Commands_SETINTERFACE):
			DBGDEBUG("Set Interface\n");
			return do_set_interface(B, cmd, sdk_lock);
			break;
		case ns(Commands_DELINTERFACE):
			DBGDEBUG("Del interface\n");
			return do_del_interface(B, cmd, sdk_lock);
			break;
		case ns(Commands_GETLEASE):
			DBGDEBUG("Get Lease\n");
			return do_get_lease(B, cmd, sdk_lock);
			break;
		case ns(Commands_GETDEFAULTROUTE):
			DBGDEBUG("Get Default route\n");
			return do_get_default_route(B, cmd, sdk_lock);
			break;
		case ns(Commands_SETTIME):
			DBGDEBUG("Set Time\n");
			return do_set_time(B, cmd);
			break;
		case ns(Commands_GETTIME):
			DBGDEBUG("Get Time\n");
			return do_get_time(B);
			break;
		case ns(Commands_NTPDATE):
			DBGDEBUG("NTPDATE\n");
			return do_issue_ntpdate(B, cmd);
			break;
		case ns(Commands_GETPROFILELIST):
			DBGDEBUG("GETPROFILELIST\n");
			return do_get_profile_list(B, sdk_lock);
			break;
		case ns(Commands_GETSCANLIST):
			DBGDEBUG("GETSCANLIST");
			return do_get_scanlist(B, sdk_lock);
			break;
		case ns(Commands_FILEPUSH):
			DBGDEBUG("FILEPUSH\n");
			return do_receive_file(B, cmd, sdk_lock, chan);
			break;
		case ns(Commands_FILEPULL):
			DBGDEBUG("FILEPULL\n");
			return do_send_file(B, cmd, NULL, sdk_lock, chan);
			break;
		case ns(Commands_FWUPDATE):
			DBGDEBUG("FWUPDATE\n");
			return do_fw_update(B, cmd, sdk_lock);
			break;
		case ns(Commands_SWUPDATE):
			DBGDEBUG("SWUPDATE\n");
			return do_swupdate(B, cmd);
			break;
		case ns(Commands_CLIFILE):
			DBGDEBUG("CLIFILE\n");
			return do_process_cli_file(B, cmd, sdk_lock);
			break;
		case ns(Commands_GETLOGS):
			DBGDEBUG("GETLOGS\n");
			return do_get_logs(B, cmd, sdk_lock, chan);
			break;
		default:
			DBGDEBUG("unknown command: %d\n",ns(Command_command(cmd)));
			return SDCERR_NOT_IMPLEMENTED;
	}
}

// the passed in buffer is used for the outbound buffer as well.  The
// buffer size is buf_size while the number of bytes used for inbound
// is nbytes, the number of bytes used in the outbound buffer is the
// return code. However, if the return is negative, this is an error
// that is unrecoverable and the session should be ended. (The buffer's
// content on a unrecoverable error is undefined.) A
// recoverable error is handled by putting a NACK in the return buffer
// and the error in the returned handshake table

int process_buffer(process_buf_struct * buf_struct)
{
	flatcc_builder_t builder;
	flatcc_builder_init(&builder);
	int ret, nbytes;
	flatbuffers_thash_t buftype;
	char ** const buf = &buf_struct->buf;
	size_t * const buf_size = &buf_struct->buf_size;

	//TODO: enable hexdump for most verbose debug setting
	//hexdump("read buffer", buf, nbytes, stdout);
	buftype = verify_buffer(*buf, *buf_size);
	if (buftype==0){
		DBGERROR("could not verify buffer.  Sending NACK - line:%d\n",__LINE__);
		ret = DCAL_FLATBUFF_VALIDATION_FAIL;
		goto respond_with_nack;
	}

	DBGINFO("incoming buffer has type: %s\n", buftype_to_string(buftype));

	if ((buf_struct->verify_handshake) && (buftype != ns(Handshake_type_hash))){
		DBGERROR("wanted a handshake but this has type: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_VALIDATION_FAIL;
		goto respond_with_nack;
	}

	switch(buftype) {
		case ns(Handshake_type_hash):
			DBGINFO("inbound handshake buffer received\n");
			if (is_handshake_valid(ns(Handshake_as_root(*buf)))) {
				DBGINFO("Got good protocol HELLO\n");
				build_handshake_ack(&builder, 0);
				goto respond_normal;
			}
			// not a valid handshake - respond with nack
			ret = DCAL_FLATBUFF_VALIDATION_FAIL;
			goto respond_with_nack;
			break;
		case ns(Command_type_hash):
			// process command
			if ((ret=process_command(&builder, ns(Command_as_root(*buf)), buf_struct->sdk_lock, buf_struct->exit_called, buf_struct->chan))){
				// un-recoverable errors will be negative
				if (ret > 0)
					goto respond_with_nack;
				// unrecoverable error
				nbytes = ret;
				goto respond_with_error;
			}
			// no error
			goto respond_normal;
			break;
		default:
			DBGINFO("failed to get HELLO\n");
			ret = DCAL_FLATBUFF_ERROR;
			goto respond_with_nack;
	}

respond_with_nack:
	build_handshake_ack(&builder, ret);
respond_normal:
	nbytes =flatcc_builder_get_buffer_size(&builder);
	if (nbytes > *buf_size) {
		DBGINFO("Buffer size too small - calling realloc() with size %d\n", nbytes);
		char * tmp = realloc(*buf, nbytes);
		if (tmp==NULL){
			DBGERROR("Error: unable to realloc() memory\n");
			build_handshake_ack(&builder, DCAL_NO_MEMORY);
			goto respond_normal;  // initial buf_size is large enough for a NACK
		}else{
			*buf = tmp;
			*buf_size = nbytes;
		}
	}
	flatcc_builder_copy_buffer(&builder, *buf, *buf_size);
	DBGDEBUG("Created response buffer type: %s; size: %zd\n",
	           buftype_to_string(verify_buffer(*buf, nbytes)), nbytes);
	//hexdump("outbound buffer", buf, nbytes, stdout);
respond_with_error: // allow for exit with 0 or negative return
	flatcc_builder_clear(&builder);

	buftype = verify_buffer(*buf, nbytes);
	DBGINFO("outbound buf is type %s\n", buftype_to_string( buftype ));
	return nbytes;
}
