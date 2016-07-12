/*
 * hostapd / main()
 * Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "crypto/tls.h"
#include "common/version.h"
#include "drivers/driver.h"
#include "eap_server/eap.h"
#include "eap_server/tncs.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"


extern int wpa_debug_level;
extern int wpa_debug_show_keys;
extern int wpa_debug_timestamp;


struct hapd_interfaces {
	size_t count;
	struct hostapd_iface **iface;
};


static int hostapd_for_each_interface(struct hapd_interfaces *interfaces,
				      int (*cb)(struct hostapd_iface *iface,
						void *ctx), void *ctx)
{
	size_t i;
	int ret;

	for (i = 0; i < interfaces->count; i++) {
		ret = cb(interfaces->iface[i], ctx);
		if (ret)
			return ret;
	}

	return 0;
}


/**
 * hostapd_init - Allocate and initialize per-interface data
 * @config_file: Path to the configuration file
 * Returns: Pointer to the allocated interface data or %NULL on failure
 *
 * This function is used to allocate main data structures for per-interface
 * data. The allocated data buffer will be freed by calling
 * hostapd_cleanup_iface().
 */
static struct hostapd_iface * hostapd_init(const char *config_file)
{
	struct hostapd_iface *hapd_iface = NULL;
	struct hostapd_config *conf = NULL;
	struct hostapd_data *hapd;
	size_t i;

	hapd_iface = os_zalloc(sizeof(*hapd_iface));
	if (hapd_iface == NULL)
		goto fail;

	hapd_iface->for_each_interface = hostapd_for_each_interface;

	hapd_iface->num_bss = HOSTAPD_NUM_BSS;
	hapd_iface->bss = os_zalloc(hapd_iface->num_bss *
				    sizeof(struct hostapd_data *));
	if (hapd_iface->bss == NULL)
		goto fail;

	for (i = 0; i < hapd_iface->num_bss; i++) {
		hapd = hapd_iface->bss[i] =
			hostapd_alloc_bss_data(hapd_iface, conf,
					       &conf->bss[i]);
		if (hapd == NULL)
			goto fail;
		hapd->msg_ctx = hapd;
	}

	return hapd_iface;

fail:
	if (hapd_iface) {
		os_free(hapd_iface->bss);
		os_free(hapd_iface);
	}
	return NULL;
}


static int hostapd_driver_init(struct hostapd_iface *iface)
{
	struct wpa_init_params params;
	size_t i;
	struct hostapd_data *hapd = iface->bss[0];
	struct hostapd_bss_config *conf = hapd->conf;
	u8 *b = conf->bssid;

	if (hapd->driver == NULL || hapd->driver->hapd_init == NULL) {
		wpa_printf(MSG_ERROR, "No hostapd driver wrapper available");
		return -1;
	}

	/* Initialize the driver interface */
	if (!(b[0] | b[1] | b[2] | b[3] | b[4] | b[5]))
		b = NULL;

	os_memset(&params, 0, sizeof(params));
	params.bssid = b;
	params.ifname = hapd->conf->iface;
	params.ssid = (const u8 *) hapd->conf->ssid.ssid;
	params.ssid_len = hapd->conf->ssid.ssid_len;
	params.test_socket = hapd->conf->test_socket;
	params.use_pae_group_addr = hapd->conf->use_pae_group_addr;

	params.num_bridge = hapd->iface->num_bss;
	params.bridge = os_zalloc(hapd->iface->num_bss * sizeof(char *));
	if (params.bridge == NULL)
		return -1;
	for (i = 0; i < hapd->iface->num_bss; i++) {
		struct hostapd_data *bss = hapd->iface->bss[i];
		if (bss->conf->bridge[0])
			params.bridge[i] = bss->conf->bridge;
	}

	params.own_addr = hapd->own_addr;

	hapd->drv_priv = hapd->driver->hapd_init(hapd, &params);
	os_free(params.bridge);
	if (hapd->drv_priv == NULL) {
		wpa_printf(MSG_ERROR, "%s driver initialization failed.",
			   hapd->driver->name);
		hapd->driver = NULL;
		return -1;
	}

	return 0;
}


static void hostapd_interface_deinit_free(struct hostapd_iface *iface)
{
	const struct wpa_driver_ops *driver;
	void *drv_priv;
	if (iface == NULL)
		return;
	driver = iface->bss[0]->driver;
	drv_priv = iface->bss[0]->drv_priv;
	hostapd_interface_deinit(iface);
	if (driver && driver->hapd_deinit)
		driver->hapd_deinit(drv_priv);
	hostapd_interface_free(iface);
}


static struct hostapd_iface *
hostapd_interface_init(struct hapd_interfaces *interfaces,
		       const char *config_fname, int debug)
{
	struct hostapd_iface *iface;
	int k;

	wpa_printf(MSG_ERROR, "Configuration file: %s", config_fname);
	iface = hostapd_init(config_fname);
	if (!iface)
		return NULL;
	iface->interfaces = interfaces;

	for (k = 0; k < debug; k++) {
		if (iface->bss[0]->conf->logger_stdout_level > 0)
			iface->bss[0]->conf->logger_stdout_level--;
	}

	if (hostapd_driver_init(iface) ||
	    hostapd_setup_interface(iface)) {
		hostapd_interface_deinit_free(iface);
		return NULL;
	}

	return iface;
}


/**
 * handle_term - SIGINT and SIGTERM handler to terminate hostapd process
 */
static void handle_term(int sig, void *signal_ctx)
{
	wpa_printf(MSG_DEBUG, "Signal %d received - terminating", sig);
	eloop_terminate();
}


static int hostapd_global_init(struct hapd_interfaces *interfaces)
{
	/*hostapd_logger_register_cb(hostapd_logger_cb);*/

	/*if (eap_server_register_methods()) {
		wpa_printf(MSG_ERROR, "Failed to register EAP methods");
		return -1;
	}*/

	if (eloop_init()) {
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
		return -1;
	}

	eloop_register_signal_terminate(handle_term, interfaces);

	return 0;
}


static void hostapd_global_deinit(void)
{
#ifdef EAP_SERVER_TNC
	tncs_global_deinit();
#endif /* EAP_SERVER_TNC */

	eloop_destroy();

	/*eap_server_unregister_methods();*/
}


static int hostapd_global_run(struct hapd_interfaces *ifaces)
{
#ifdef EAP_SERVER_TNC
	int tnc = 0;
	size_t i, k;

	for (i = 0; !tnc && i < ifaces->count; i++) {
		for (k = 0; k < ifaces->iface[i]->num_bss; k++) {
			if (ifaces->iface[i]->bss[0]->conf->tnc) {
				tnc++;
				break;
			}
		}
	}

	if (tnc && tncs_global_init() < 0) {
		wpa_printf(MSG_ERROR, "Failed to initialize TNCS");
		return -1;
	}
#endif /* EAP_SERVER_TNC */

	eloop_run();

	return 0;
}


int main(int argc, char *argv[])
{
	struct hapd_interfaces interfaces;
	int ret = 1;
	size_t i;
	int debug = 0;

	interfaces.count = argc - optind;
	interfaces.iface = os_malloc(interfaces.count *
				     sizeof(struct hostapd_iface *));
	if (interfaces.iface == NULL) {
		wpa_printf(MSG_ERROR, "malloc failed\n");
		return -1;
	}

	if (hostapd_global_init(&interfaces))
		return -1;

	/* Initialize interfaces */
	for (i = 0; i < interfaces.count; i++) {
		interfaces.iface[i] = hostapd_interface_init(&interfaces,
							     argv[optind + i],
							     debug);
		if (!interfaces.iface[i])
			goto out;
	}

	if (hostapd_global_run(&interfaces))
		goto out;

	ret = 0;

 out:
	/* Deinitialize all interfaces */
	for (i = 0; i < interfaces.count; i++)
		hostapd_interface_deinit_free(interfaces.iface[i]);
	os_free(interfaces.iface);

	hostapd_global_deinit();

	return ret;
}
