ifdef CONFIG_ARCH
-include $(TOPDIR)/.config
endif

all:
ifdef CONFIG_ARCH
ifeq ($(CONFIG_WIFI_STA),y)
	$(Q) $(MAKE) -C wpa_supplicant CONFIG_ARCH="$(CONFIG_ARCH)"
endif
ifeq ($(CONFIG_WIFI_AP),y)
	$(Q) $(MAKE) -C hostapd CONFIG_ARCH="$(CONFIG_ARCH)"
endif
	$(Q) cp -r libwifi.a $(TOPDIR)/lib/
else
	$(Q) $(MAKE) -C wpa_supplicant
	$(Q) $(MAKE) -C hostapd
endif

clean:
ifdef CONFIG_ARCH
ifeq ($(CONFIG_WIFI_STA),y)
	$(Q) $(MAKE) -C wpa_supplicant clean
endif
ifeq ($(CONFIG_WIFI_AP),y)
	$(Q) $(MAKE) -C hostapd clean
endif
else
	$(Q) $(MAKE) -C wpa_supplicant clean
	$(Q) $(MAKE) -C hostapd clean
endif

distclean:
ifdef CONFIG_ARCH
ifeq ($(CONFIG_WIFI_STA),y)
	$(Q) $(MAKE) -C wpa_supplicant distclean
endif
ifeq ($(CONFIG_WIFI_AP),y)
	$(Q) $(MAKE) -C hostapd distclean
endif
else
	$(Q) $(MAKE) -C wpa_supplicant distclean
	$(Q) $(MAKE) -C hostapd distclean
endif
