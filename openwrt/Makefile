include $(TOPDIR)/rules.mk

PKG_NAME:=umurmur_12x
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/umurmur_12x
	SECTION:=net
	CATEGORY:=Network
	TITLE:=uMurmur_12x
	DEPENDS:=+libopenssl +libconfig
	URL:=http://code.google.com/p/umurmur
	MAINTAINER:=Martin Johansson <martin@fatbob.nu>
endef

define Package/umurmur_12x/description
	Minimalistic Mumble server daemon.
endef

TARGET_CFLAGS := \
        -DWRT_TARGET \
        $(TARGET_CFLAGS)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/CompileTarget
	CFLAGS="$(TARGET_CFLAGS)" LDFLAGS="$(TARGET_LDFLAGS)"\
	$(MAKE) -C $(PKG_BUILD_DIR)/umurmur_12x.$(1)/umurmur_12x \
		all
endef

define Package/umurmur_12x/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/umurmur_12x $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_CONF) ./files/umurmur.conf $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/umurmur.init $(1)/etc/init.d/umurmur_12x
	$(INSTALL_DIR) $(1)/etc/umurmur
endef

$(eval $(call BuildPackage,umurmur_12x))

