#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "debug.h"
#include "version.h"
#include "sdc_sdk.h"
#include "buffer.h"

#include "dcal_builder.h"
#include "dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)
#include "support/hexdump.h"

#define LAIRD_HELLO "HELLO DCAS"
#define LAIRD_RESPONSE "WELCOME TO FAIRFIELD"
#define LAIRD_BAD_BUFFER "BAD FLAT BUFFER"

#define SDKLOCK(x) (pthread_mutex_lock(x))
#define SDKUNLOCK(x) (pthread_mutex_unlock(x))

int is_handshake_valid(void *buffer, size_t size)
{
	ns(Handshake_table_t) handshake;
	const char * ip;
	int ret;

	if((ret = ns(Handshake_verify_as_root(buffer, size, ns(Handshake_identifier))))){
		DBGERROR("could not verify buffer, got %s\n", flatcc_verify_error_string(ret));
		return 0;
	}

	if (!(handshake = ns(Handshake_as_root(buffer)))) {
		DBGERROR("Not a handshake\n");
		return 0;
	}

	if (ns(Handshake_server(handshake)) == true) {
		DBGERROR("Handshake marked as from server\n");
		return 0;
	}

	ip = ns(Handshake_ip(handshake));
	DBGINFO("Got ip: %s\n", ip);

	if (ns(Handshake_magic(handshake)) == ns(Magic_HELLO))
		return 1;

	return 0;
}

int build_handshake_ack(flatcc_builder_t *B, ns(Magic_enum_t) res_code)
{
	flatcc_builder_reset(B);
	ns(Handshake_start_as_root(B));
	ns(Handshake_server_add(B, true));
	ns(Handshake_magic_add(B, res_code));
	ns(Handshake_ip_create_str(B, "192.168.0.1"));
	ns(Handshake_end_as_root(B));
	return 0;
}

#define MAC_SZ 6
#define IP4_SZ 4
#define IP6_SZ 8

int build_status(flatcc_builder_t *B, pthread_mutex_t *sdk_lock)
{
	CF10G_STATUS status;
	SDCERR result;
	LRD_WF_SSID ssid;
	memset(&status, 0, sizeof(CF10G_STATUS));

	SDKLOCK(sdk_lock);
	result = GetCurrentStatus(&status);
	SDKUNLOCK(sdk_lock);
	if (result!=SDCERR_SUCCESS)
		DBGERROR("GetCurrentStatus() failed with %d\n", result);
	result = LRD_WF_GetSSID(&ssid);
		DBGERROR("LRD_WF_GetSSID() failed with %d\n", result);

// only dealing with client mode for now
	flatcc_builder_reset(B);
	ns(Status_start_as_root(B));
	ns(Status_cardState_add(B, status.cardState));
	ns(Status_ProfileName_create_str(B, status.configName));
	ns(Status_ssid_create_str(B, (char *)ssid.val));
	ns(Status_channel_add(B, status.channel));
	ns(Status_rssi_add(B, status.rssi));
	ns(Status_clientName_create_str(B, status.clientName));
	ns(Status_mac_create(B, (char *)status.client_MAC, MAC_SZ));
	ns(Status_ip_create(B, (char *)status.client_IP, IP4_SZ));
	ns(Status_AP_mac_create(B, (char *)status.AP_MAC, MAC_SZ));
	ns(Status_AP_ip_create(B, (char *)status.AP_IP, IP4_SZ));
	ns(Status_AP_name_create_str(B, status.APName));
	ns(Status_bitRate_add(B, status.bitRate));
	ns(Status_txPower_add(B, status.txPower));
	ns(Status_dtim_add(B, status.DTIM));
	ns(Status_beaconPeriod_add(B, status.beaconPeriod));

	ns(Status_end_as_root(B));
	return 0;
}

int processbuff(char * buf, size_t size, pthread_mutex_t *sdk_lock)
{
	flatcc_builder_t builder;
	flatcc_builder_init(&builder);
	void * handshake_buffer;
	size_t nbytes;

	hexdump("read buffer", buf, size, stdout);

	if (is_handshake_valid(buf, size)) {
			DBGINFO("Got good protocol HELLO\n");
//TODO - deal with handshake for session management
//			build_handshake_ack(&builder, ns(Magic_ACK));
			build_status(&builder, sdk_lock);
	}
	else
	{
		DBGINFO("failed to get HELLO\n");
		build_handshake_ack(&builder, ns(Magic_NACK));
	}
	handshake_buffer = flatcc_builder_get_direct_buffer(&builder, &nbytes);
	assert(handshake_buffer);
	DBGDEBUG("Created Handshake buffer size: %zd\n", nbytes);

	memcpy(buf, handshake_buffer, nbytes);
	hexdump("outbound buffer", buf, nbytes, stdout);

	flatcc_builder_clear(&builder);
	return nbytes;
}
