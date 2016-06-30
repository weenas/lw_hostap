/*
 * WPA Supplicant / Configuration file structures
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
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

#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_EAPOL_VERSION 1
#ifdef CONFIG_NO_SCAN_PROCESSING
#define DEFAULT_AP_SCAN 2
#else /* CONFIG_NO_SCAN_PROCESSING */
#define DEFAULT_AP_SCAN 1
#endif /* CONFIG_NO_SCAN_PROCESSING */
#define DEFAULT_FAST_REAUTH 1
#define DEFAULT_P2P_GO_INTENT 7
#define DEFAULT_P2P_INTRA_BSS 1
#define DEFAULT_BSS_MAX_COUNT 200

#include "config_ssid.h"


#define CFG_CHANGED_DEVICE_NAME BIT(0)
#define CFG_CHANGED_CONFIG_METHODS BIT(1)
#define CFG_CHANGED_DEVICE_TYPE BIT(2)
#define CFG_CHANGED_OS_VERSION BIT(3)
#define CFG_CHANGED_UUID BIT(4)
#define CFG_CHANGED_COUNTRY BIT(5)
#define CFG_CHANGED_SEC_DEVICE_TYPE BIT(6)
#define CFG_CHANGED_P2P_SSID_POSTFIX BIT(7)
#define CFG_CHANGED_WPS_STRING BIT(8)
#define CFG_CHANGED_P2P_INTRA_BSS BIT(9)

/**
 * struct wpa_config - wpa_supplicant configuration data
 *
 * This data structure is presents the per-interface (radio) configuration
 * data. In many cases, there is only one struct wpa_config instance, but if
 * more than one network interface is being controlled, one instance is used
 * for each.
 */
struct wpa_config {
	/**
	 * ssid - Head of the global network list
	 *
	 * This is the head for the list of all the configured networks.
	 */
	struct wpa_ssid *ssid;

	/**
	 * pssid - Per-priority network lists (in priority order)
	 */
	struct wpa_ssid *pssid;

	/**
	 * num_prio - Number of different priorities used in the pssid lists
	 *
	 * This indicates how many per-priority network lists are included in
	 * pssid.
	 */
	int num_prio;

	/**
	 * eapol_version - IEEE 802.1X/EAPOL version number
	 *
	 * wpa_supplicant is implemented based on IEEE Std 802.1X-2004 which
	 * defines EAPOL version 2. However, there are many APs that do not
	 * handle the new version number correctly (they seem to drop the
	 * frames completely). In order to make wpa_supplicant interoperate
	 * with these APs, the version number is set to 1 by default. This
	 * configuration value can be used to set it to the new version (2).
	 */
	int eapol_version;

	/**
	 * ap_scan - AP scanning/selection
	 *
	 * By default, wpa_supplicant requests driver to perform AP
	 * scanning and then uses the scan results to select a
	 * suitable AP. Another alternative is to allow the driver to
	 * take care of AP scanning and selection and use
	 * wpa_supplicant just to process EAPOL frames based on IEEE
	 * 802.11 association information from the driver.
	 *
	 * 1: wpa_supplicant initiates scanning and AP selection (default).
	 *
	 * 0: Driver takes care of scanning, AP selection, and IEEE 802.11
	 * association parameters (e.g., WPA IE generation); this mode can
	 * also be used with non-WPA drivers when using IEEE 802.1X mode;
	 * do not try to associate with APs (i.e., external program needs
	 * to control association). This mode must also be used when using
	 * wired Ethernet drivers.
	 *
	 * 2: like 0, but associate with APs using security policy and SSID
	 * (but not BSSID); this can be used, e.g., with ndiswrapper and NDIS
	 * drivers to enable operation with hidden SSIDs and optimized roaming;
	 * in this mode, the network blocks in the configuration are tried
	 * one by one until the driver reports successful association; each
	 * network block should have explicit security policy (i.e., only one
	 * option in the lists) for key_mgmt, pairwise, group, proto variables.
	 */
	int ap_scan;


	/**
	 * fast_reauth - EAP fast re-authentication (session resumption)
	 *
	 * By default, fast re-authentication is enabled for all EAP methods
	 * that support it. This variable can be used to disable fast
	 * re-authentication (by setting fast_reauth=0). Normally, there is no
	 * need to disable fast re-authentication.
	 */
	int fast_reauth;

	/**
	 * opensc_engine_path - Path to the OpenSSL engine for opensc
	 *
	 * This is an OpenSSL specific configuration option for loading OpenSC
	 * engine (engine_opensc.so); if %NULL, this engine is not loaded.
	 */
	char *opensc_engine_path;

	/**
	 * pkcs11_engine_path - Path to the OpenSSL engine for PKCS#11
	 *
	 * This is an OpenSSL specific configuration option for loading PKCS#11
	 * engine (engine_pkcs11.so); if %NULL, this engine is not loaded.
	 */
	char *pkcs11_engine_path;

	/**
	 * pkcs11_module_path - Path to the OpenSSL OpenSC/PKCS#11 module
	 *
	 * This is an OpenSSL specific configuration option for configuring
	 * path to OpenSC/PKCS#11 engine (opensc-pkcs11.so); if %NULL, this
	 * module is not loaded.
	 */
	char *pkcs11_module_path;

	/**
	 * driver_param - Driver interface parameters
	 *
	 * This text string is passed to the selected driver interface with the
	 * optional struct wpa_driver_ops::set_param() handler. This can be
	 * used to configure driver specific options without having to add new
	 * driver interface functionality.
	 */
	char *driver_param;

	/**
	 * dot11RSNAConfigPMKLifetime - Maximum lifetime of a PMK
	 *
	 * dot11 MIB variable for the maximum lifetime of a PMK in the PMK
	 * cache (unit: seconds).
	 */
	unsigned int dot11RSNAConfigPMKLifetime;

	/**
	 * dot11RSNAConfigPMKReauthThreshold - PMK re-authentication threshold
	 *
	 * dot11 MIB variable for the percentage of the PMK lifetime
	 * that should expire before an IEEE 802.1X reauthentication occurs.
	 */
	unsigned int dot11RSNAConfigPMKReauthThreshold;

	/**
	 * dot11RSNAConfigSATimeout - Security association timeout
	 *
	 * dot11 MIB variable for the maximum time a security association
	 * shall take to set up (unit: seconds).
	 */
	unsigned int dot11RSNAConfigSATimeout;

	/**
	 * update_config - Is wpa_supplicant allowed to update configuration
	 *
	 * This variable control whether wpa_supplicant is allow to re-write
	 * its configuration with wpa_config_write(). If this is zero,
	 * configuration data is only changed in memory and the external data
	 * is not overriden. If this is non-zero, wpa_supplicant will update
	 * the configuration data (e.g., a file) whenever configuration is
	 * changed. This update may replace the old configuration which can
	 * remove comments from it in case of a text file configuration.
	 */
	int update_config;


	/**
	 * uuid - Universally Unique IDentifier (UUID; see RFC 4122) for WPS
	 */
	u8 uuid[16];

	/**
	 * device_name - Device Name (WPS)
	 * User-friendly description of device; up to 32 octets encoded in
	 * UTF-8
	 */
	char *device_name;

	/**
	 * manufacturer - Manufacturer (WPS)
	 * The manufacturer of the device (up to 64 ASCII characters)
	 */
	char *manufacturer;

	/**
	 * model_name - Model Name (WPS)
	 * Model of the device (up to 32 ASCII characters)
	 */
	char *model_name;

	/**
	 * model_number - Model Number (WPS)
	 * Additional device description (up to 32 ASCII characters)
	 */
	char *model_number;

	/**
	 * serial_number - Serial Number (WPS)
	 * Serial number of the device (up to 32 characters)
	 */
	char *serial_number;

	/**
	 * device_type - Primary Device Type (WPS)
	 * Used format: categ-OUI-subcateg
	 * categ = Category as an integer value
	 * OUI = OUI and type octet as a 4-octet hex-encoded value;
	 *	0050F204 for default WPS OUI
	 * subcateg = OUI-specific Sub Category as an integer value
	 * Examples:
	 *   1-0050F204-1 (Computer / PC)
	 *   1-0050F204-2 (Computer / Server)
	 *   5-0050F204-1 (Storage / NAS)
	 *   6-0050F204-1 (Network Infrastructure / AP)
	 */
	char *device_type;

	/**
	 * config_methods - Config Methods
	 *
	 * This is a space-separated list of supported WPS configuration
	 * methods. For example, "label virtual_display virtual_push_button
	 * keypad".
	 * Available methods: usba ethernet label display ext_nfc_token
	 * int_nfc_token nfc_interface push_button keypad
	 * virtual_display physical_display
	 * virtual_push_button physical_push_button.
	 */
	char *config_methods;

	/**
	 * os_version - OS Version (WPS)
	 * 4-octet operating system version number
	 */
	u8 os_version[4];

	/**
	 * country - Country code
	 *
	 * This is the ISO/IEC alpha2 country code for which we are operating
	 * in
	 */
	char country[2];

	/**
	 * wps_cred_processing - Credential processing
	 *
	 *   0 = process received credentials internally
	 *   1 = do not process received credentials; just pass them over
	 *	ctrl_iface to external program(s)
	 *   2 = process received credentials internally and pass them over
	 *	ctrl_iface to external program(s)
	 */
	int wps_cred_processing;

#define MAX_SEC_DEVICE_TYPES 5
	/**
	 * sec_device_type - Secondary Device Types (P2P)
	 * See device_type for the format used with these.
	 */
	char *sec_device_type[MAX_SEC_DEVICE_TYPES];

	int p2p_listen_reg_class;
	int p2p_listen_channel;
	int p2p_oper_reg_class;
	int p2p_oper_channel;
	int p2p_go_intent;
	char *p2p_ssid_postfix;
	int persistent_reconnect;
	int p2p_intra_bss;

	/**
	 * bss_max_count - Maximum number of BSS entries to keep in memory
	 */
	unsigned int bss_max_count;

	/**
	 * filter_ssids - SSID-based scan result filtering
	 *
	 *   0 = do not filter scan results
	 *   1 = only include configured SSIDs in scan results/BSS table
	 */
	int filter_ssids;

	/**
	 * changed_parameters - Bitmap of changed parameters since last update
	 */
	unsigned int changed_parameters;
};


/* Prototypes for common functions from config.c */

void wpa_config_free(struct wpa_config *ssid);
void wpa_config_free_ssid(struct wpa_ssid *ssid);
struct wpa_ssid * wpa_config_get_network(struct wpa_config *config, int id);
struct wpa_ssid * wpa_config_add_network(struct wpa_config *config);
int wpa_config_remove_network(struct wpa_config *config, int id);
void wpa_config_set_network_defaults(struct wpa_ssid *ssid);
int wpa_config_set(struct wpa_ssid *ssid, const char *var, const char *value,
		   int line);
char ** wpa_config_get_all(struct wpa_ssid *ssid, int get_keys);
char * wpa_config_get(struct wpa_ssid *ssid, const char *var);
char * wpa_config_get_no_key(struct wpa_ssid *ssid, const char *var);
void wpa_config_update_psk(struct wpa_ssid *ssid);
int wpa_config_add_prio_network(struct wpa_config *config,
				struct wpa_ssid *ssid);
int wpa_config_update_prio_list(struct wpa_config *config);
const struct wpa_config_blob * wpa_config_get_blob(struct wpa_config *config,
						   const char *name);
void wpa_config_set_blob(struct wpa_config *config,
			 struct wpa_config_blob *blob);
void wpa_config_free_blob(struct wpa_config_blob *blob);
int wpa_config_remove_blob(struct wpa_config *config, const char *name);

struct wpa_config * wpa_config_alloc_empty(const char *ctrl_interface,
					   const char *driver_param);
#ifndef CONFIG_NO_STDOUT_DEBUG
void wpa_config_debug_dump_networks(struct wpa_config *config);
#else /* CONFIG_NO_STDOUT_DEBUG */
#define wpa_config_debug_dump_networks(c) do { } while (0)
#endif /* CONFIG_NO_STDOUT_DEBUG */

#endif /* CONFIG_H */
