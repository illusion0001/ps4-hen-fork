#ifndef PATH_H_
#define PATH_H_

#define BASE_PATH "/data/hen"
#define BASE_USER_PLUGINS_PATH "/data/hen/plugins"
#define HEN_INI "hen.ini"
#define VERSION_TXT "version.txt"
#define HDD_INI_PATH BASE_PATH "/" HEN_INI
#define USB_INI_PATH "/mnt/usb0/" HEN_INI
#define PRX_BOOTLOADER_PATH BASE_PATH "/plugin_bootloader.prx"
#define PRX_LOADER_PATH BASE_PATH "/plugin_loader.prx"
#define PRX_SERVER_PATH BASE_PATH "/plugin_server.prx"
#define PRX_MONO_PATH BASE_PATH "/plugin_mono.prx"
#define PRX_SHELLCORE_PATH BASE_PATH "/plugin_shellcore.prx"
#define PRX_GAMEPATCH_PATH BASE_USER_PLUGINS_PATH "/plugin_game_patch.prx"
#define IS_INSTALLED_PATH "/user/temp/hen.installed"
#define IS_SHELLCORE_APPINFO_INSTALLED_PATH "/user/temp/shellcore_appinfo.installed"

#endif
