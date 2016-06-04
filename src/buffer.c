#define _BSD_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "debug.h"
#include "version.h"
#include "sdc_sdk.h"
#include "buffer.h"
#undef SSID_SZ //TODO - use a different define so no collision on different values for same named #define
#include "dcal_api.h"

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
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Status_type_hash):
			if(ns(Status_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Command_type_hash):
			if(ns(Command_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(U32_type_hash):
			if(ns(U32_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Version_type_hash):
			if(ns(Version_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Globals_type_hash):
			if(ns(Globals_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Profile_type_hash):
			if(ns(Profile_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Profiles_type_hash):
			if(ns(Profiles_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
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
		case ns(Profiles_type_hash):
			return "Profiles";
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

int build_handshake_ack(flatcc_builder_t *B, ns(Magic_enum_t) res_code, unsigned int error)
{
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Handshake_type_identifier));
	ns(Handshake_start(B));
	ns(Handshake_server_add(B, true));
	ns(Handshake_magic_add(B, res_code));
	//TODO - do we want our ip address in the handshake from server?  If so
	//we need to get from the ssh session somehow so we know what interface
	//Could have it included by default in process_buffer call
//	ns(Handshake_ip_create_str(B, "192.168.0.1"));
	ns(Handshake_api_level_add(B, DCAL_API_VERSION));
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
		DBGERROR("LRD_WF_GetSSID() failed with %d\n", result);
		// there are conditions such as disabled where this could fail and we
		// don't want to abort sending back status, so no return here.
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
	dcas = DCAL_API_VERSION;
	driver = status.driverVersion;

	FILE *in = popen( "sdcsupp -qv", "r");
	if (in){
		fgets(supplicant, STR_SZ, in);
		supplicant[STR_SZ-1]=0;
		pclose(in);
	} else
		strcpy(supplicant, "none");

	int sysfile = open ("/etc/laird-release", O_RDONLY);
	if ((sysfile==-1) && (errno==ENOENT))
		sysfile = open ("/etc/summit-release", O_RDONLY);
	if (sysfile > 1){
		read(sysfile, release, STR_SZ);
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

	build_handshake_ack(B, ns(Magic_ACK), 0);
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

#define weplen(s) ((strlen(s)==5)?WEPLEN_40BIT:(strlen(s)==16)?WEPLEN_128BIT:WEPLEN_NOT_SET)

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int do_set_profile(flatcc_builder_t *B, ns(Command_table_t) cmd, pthread_mutex_t *sdk_lock)
{
	ns(Profile_table_t) profile;
	SDCConfig config = {{0}};
	int ret;

	profile = ns(Command_cmd_pl(cmd));

	strncpy(config.configName, ns(Profile_name(profile)), CONFIG_NAME_SZ);
	assert(flatbuffers_uint8_vec_len(ns(Profile_ssid(profile))) <= SSID_SZ);

	memcpy(&config.SSID, ns(Profile_ssid(profile)), flatbuffers_uint8_vec_len(ns(Profile_ssid(profile))));

	strncpy(config.clientName, ns(Profile_client_name(profile)), CLIENT_NAME_SZ);

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
		case WEP_AUTO:
			ret = SetMultipleWEPKeys( &config, ns(Profile_weptxkey(profile)),
			                      weplen(ns(Profile_security1(profile))),
			                      (unsigned char*)ns(Profile_security1(profile)),
			                      weplen(ns(Profile_security2(profile))),
			                      (unsigned char*)ns(Profile_security2(profile)),
			                      weplen(ns(Profile_security3(profile))),
			                      (unsigned char*)ns(Profile_security3(profile)),
			                      weplen(ns(Profile_security4(profile))),
			                      (unsigned char*)ns(Profile_security4(profile)));
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
				case EAP_NONE:
				case EAP_WAPI_CERT:
					// do nothing
					break;
				case EAP_LEAP:
					SetLEAPCred(&config, user(profile), password(profile));
					break;
				case EAP_EAPTTLS:
				case EAP_PEAPMSCHAP:
				case EAP_PEAPGTC:
					SetPEAPGTCCred(&config, user(profile), password(profile), CERT_FILE, cacert(profile));
					break;
				case EAP_EAPFAST:
					SetEAPFASTCred(&config, user(profile), password(profile), pacfilename(profile), pacpassword(profile));
					break;
				case EAP_EAPTLS:
				case EAP_PEAPTLS:
					SetEAPTLSCred(&config, user(profile), usercert(profile), CERT_FILE, cacert(profile));
				break;
			}
	}

	SDKLOCK(sdk_lock);
	ret = AddConfig(&config);
	if (ret==SDCERR_INVALID_NAME)
		ret = ModifyConfig(config.configName, &config);
	SDKUNLOCK(sdk_lock);
	build_handshake_ack(B, ns(Magic_ACK), ret);
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
	build_handshake_ack(B, ns(Magic_ACK), ret);
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
	build_handshake_ack(B, ns(Magic_ACK), ret);
	return ret;
}

//return codes:
//0 - success
//positive value - benign error
//negative value - unrecoverable error
int process_command(flatcc_builder_t *B, ns(Command_table_t) cmd,
 pthread_mutex_t *sdk_lock, bool *exit_called)
{
	switch(ns(Command_command(cmd))){
		case ns(Commands_GETSTATUS):
			return build_status(B, sdk_lock);
			break;
		case ns(Commands_GETVERSION):
			return build_version(B, sdk_lock);
			break;
		case ns(Commands_WIFIENABLE):
		case ns(Commands_WIFIDISABLE):
			return do_enable_disable(B, sdk_lock,
			          ns(Command_command(cmd))==ns(Commands_WIFIENABLE));
			break;
		case ns(Commands_SETPROFILE):
			return do_set_profile(B, cmd, sdk_lock);
			break;
		case ns(Commands_ACTIVATEPROFILE):
			return do_activate_profile(B, cmd, sdk_lock);
			break;
		case ns(Commands_WIFIRESTART):
			return do_issue_radiorestart(B, sdk_lock);
			break;
		case ns(Commands_SYSTEMREBOOT):
			build_handshake_ack(B, ns(Magic_ACK), 0);
			*exit_called = true;
			return 0;
			break;
//TODO - add other command processing
		case ns(Commands_GETPROFILE):
		case ns(Commands_GETPROFILES):
			return SDCERR_NOT_IMPLEMENTED;
		default:
			return 0;
	}
}

// the passed in buffer is used for the outbound buffer as well.  The buffer
// size is buf_size while the number of bytes used for inbound is nbytes
// the number of bytes used in the outbound buffer is the return code.
// However, if the return is negative, this is an error that is
// unrecoverable and the session should be ended.  An error in with the
// contents of the buffer are handled by putting a NACK in the return buffer

int process_buffer(char * buf, size_t buf_size, size_t nbytes, pthread_mutex_t *sdk_lock, bool must_be_handshake, bool *exit_called)
{
	flatcc_builder_t builder;
	flatcc_builder_init(&builder);
	int ret;
	flatbuffers_thash_t buftype;

	//hexdump("read buffer", buf, nbytes, stdout);

	buftype = verify_buffer(buf, nbytes);
	if (buftype==0){
		DBGERROR("could not verify buffer.  Sending NACK\n");
		ret = DCAL_FLATBUFF_VALIDATION_FAIL;
		goto respond_with_nack;
	}

	DBGINFO("incoming buffer has type: %s\n", buftype_to_string(buftype));

	if ((must_be_handshake) && (buftype != ns(Handshake_type_hash))){
		DBGERROR("wanted a handshake but this is: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_VALIDATION_FAIL;
		goto respond_with_nack;
	}

	switch(buftype) {
		case ns(Handshake_type_hash):
			DBGINFO("inbound handshake buffer received\n");
			if (is_handshake_valid(ns(Handshake_as_root(buf)))) {
				DBGINFO("Got good protocol HELLO\n");
				build_handshake_ack(&builder, ns(Magic_ACK), 0);
				goto respond_normal;
			}
			// not a valid handshake - respond with nack
			ret = DCAL_FLATBUFF_VALIDATION_FAIL;
			goto respond_with_nack;
			break;
		case ns(Command_type_hash):
			// process command
			if ((ret=process_command(&builder, ns(Command_as_root(buf)), sdk_lock, exit_called))){
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
	build_handshake_ack(&builder, ns(Magic_NACK), ret);
respond_normal:
	flatcc_builder_copy_buffer(&builder, buf, buf_size);
	nbytes =flatcc_builder_get_buffer_size(&builder);
	DBGDEBUG("Created response buffer size: %zd\n", nbytes);
	hexdump("outbound buffer", buf, nbytes, stdout);
respond_with_error: // allow for exit with 0 or negative return
	flatcc_builder_clear(&builder);
	return nbytes;
}
