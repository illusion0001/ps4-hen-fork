// #define DEBUG_SOCKET
#define DEBUG_IP "192.168.2.2"
#define DEBUG_PORT 9023

#define VERSION "2.2.0 BETA"

#include "defines.h"
#include "offsets.h"

#include <stdbool.h>
#include <ps4.h>

// will force rebuild because its translation unit to be built first
// static won't redefine these symbols here
#include "plugin_bootloader.prx.inc.c"
#include "plugin_loader.prx.inc.c"
#include "plugin_server.prx.inc.c"
#include "kpayload.inc.c"

#define DEFAULT_DISABLE_ASLR 1 // Disable ASLR by default
#define DEFAULT_NOBD_PATCHES 0 // Skip NoBD patches by default
#define TARGET_ID_SIZE 4 // eg. 0x84

typedef struct {
  int disable_aslr;
  int nobd_patches;
  char target_id[TARGET_ID_SIZE + 1]; // Add null term
} configuration;

// The return values are flipped in this function compared to the rest of this
// file becuase the INI lib expects it that way
int config_handler(void *config, const char *name, const char *value) {
  configuration *config_p = (configuration *)config;

#define MATCH(n) strcmp(name, n) == 0
  if (MATCH("disable_aslr")) {
    int temp = atoi(value);
    if (temp != 0 && temp != 1) {
      printf_notification("ERROR: Invalid disable_aslr:\n    Must be 0 or 1");
      config_p->disable_aslr = DEFAULT_DISABLE_ASLR;
    } else {
      config_p->disable_aslr = temp;
    }
  } else if (MATCH("nobd_patches")) {
    int temp = atoi(value);
    if (temp != 0 && temp != 1) {
      printf_notification("ERROR: Invalid nobd_patches:\n    Must be 0 or 1");
      config_p->nobd_patches = DEFAULT_NOBD_PATCHES;
    } else {
      config_p->nobd_patches = temp;
    }
  } else if (MATCH("target_id")) {
    if (strlen(value) == 1 && value[0] == '0') {
      memset(config_p->target_id, '\0', sizeof(config_p->target_id));
    } else if (strlen(value) != TARGET_ID_SIZE) {
      printf_notification("ERROR: Malformed target_id:\n    Must be %i bytes (e.g. 0x84)", TARGET_ID_SIZE);
    } else if (value[0] != '0' || value[1] != 'x' || !isxdigit(value[2]) || !isxdigit(value[3])) {
      printf_notification("ERROR: Malformed target_id:\n    Incorrect format, must be 0x?? (e.g. 0x84)");
    } else if (!((tolower(value[2]) == '8' && ((value[3] >= '0' && value[3] <= '9') || (tolower(value[3]) >= 'a' && tolower(value[3]) <= 'f'))) || (tolower(value[2]) == 'a' && value[3] == '0'))) {
      // Trust the clusterfuck of an if statement above is correct
      printf_notification("ERROR: Unknown target_id:\n    Only 0x80-0x8F and 0xA0 are valid");
    } else {
      memcpy(config_p->target_id, value, TARGET_ID_SIZE);
      config_p->target_id[TARGET_ID_SIZE] = '\0';
    }
  } else {
    return 0;
  }

  return 1;
}

// Return 0 on success
// Return -1 on unsupported firmware error
// Can also just give a memory error in the browser or panic the console on failure
int kpayload_patches(struct thread *td, struct kpayload_firmware_args *args) {
  UNUSED(td);
  void *kernel_base;
  uint8_t *kernel_ptr;

  // Use "kmem" for all patches
  uint8_t *kmem;

  // Pointers to be assigned in build_kpayload macro
  uint8_t *uart_patch;
  // uint8_t *is_diag_process_patch;
  // uint8_t *allow_system_level_logging_patch;
  // uint8_t *allow_coredump_patch;
  uint8_t *copyin_patch_1;
  uint8_t *copyin_patch_2;
  uint8_t *copyout_patch_1;
  uint8_t *copyout_patch_2;
  uint8_t *copyinstr_patch_1;
  uint8_t *copyinstr_patch_2;
  uint8_t *copyinstr_patch_3;
  uint8_t *setlogin_patch;
  uint8_t *pfs_signature_check_patch;
  uint8_t *debug_rif_patch_1;
  uint8_t *debug_rif_patch_2;
  uint8_t *debug_settings_error_patch_1;
  uint8_t *debug_settings_error_patch_2;
  // uint8_t *mount_patch;
  uint8_t *depth_limit_patch;

  uint16_t fw_version = args->kpayload_firmware_info->fw_version;

  // NOTE: This is a C preprocessor macro
  build_kpayload(fw_version, patch_macro);

  // Disable write protection
  uint64_t cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);

  // Enable UART
  kmem = (uint8_t *)uart_patch;
  kmem[0] = 0x00;

  // sceSblACMgrIsDiagProcess
  // kmem = (uint8_t *)is_diag_process_patch;
  // kmem[0] = 0xB8;
  // kmem[1] = 0x01;
  // kmem[2] = 0x00;
  // kmem[3] = 0x00;
  // kmem[4] = 0x00;
  // kmem[5] = 0xC3;

  // sceSblACMgrIsAllowedSystemLevelDebugging
  // kmem = (uint8_t *)allow_system_level_logging_patch;
  // kmem[0] = 0xB8;
  // kmem[1] = 0x01;
  // kmem[2] = 0x00;
  // kmem[3] = 0x00;
  // kmem[4] = 0x00;
  // kmem[5] = 0xC3;

  // sceSblACMgrIsAllowedCoredump
  // kmem = (uint8_t *)allow_coredump_patch;
  // kmem[0] = 0xB8;
  // kmem[1] = 0x01;
  // kmem[2] = 0x00;
  // kmem[3] = 0x00;
  // kmem[4] = 0x00;
  // kmem[5] = 0xC3;

  // Patch copyin/copyout/copyinstr to allow userland + kernel addresses in both params
  // copyin
  kmem = (uint8_t *)copyin_patch_1;
  kmem[0] = 0xEB;
  kmem[1] = 0x00;

  if (fw_version >= 550) {
    kmem = (uint8_t *)copyin_patch_2;
    kmem[0] = 0xEB;
    kmem[1] = 0x01;
  }

  kmem = (uint8_t *)copyout_patch_1;
  kmem[0] = 0xEB;
  kmem[1] = 0x00;

  if (fw_version >= 550) {
    kmem = (uint8_t *)copyout_patch_2;
    kmem[0] = 0xEB;
    kmem[1] = 0x01;
  }

  // copyinstr
  kmem = (uint8_t *)copyinstr_patch_1;
  kmem[0] = 0xEB;
  kmem[1] = 0x00;

  if (fw_version >= 550) {
    kmem = (uint8_t *)copyinstr_patch_2;
    kmem[0] = 0xEB;
    kmem[1] = 0x01;
  }

  kmem = (uint8_t *)copyinstr_patch_3;
  kmem[0] = 0xEB;
  kmem[1] = 0x00;

  // setlogin patch (for autolaunch check)
  kmem = (uint8_t *)setlogin_patch;
  kmem[0] = 0x48;
  kmem[1] = 0x31;
  kmem[2] = 0xC0;
  kmem[3] = 0xEB;
  kmem[4] = 0x00;

  // Disable PFS signature check
  kmem = (uint8_t *)pfs_signature_check_patch;
  kmem[0] = 0x31;
  kmem[1] = 0xC0;
  kmem[2] = 0xC3;

  // Enable debug RIFs
  kmem = (uint8_t *)debug_rif_patch_1;
  kmem[0] = 0xB0;
  kmem[1] = 0x01;
  kmem[2] = 0xC3;

  kmem = (uint8_t *)debug_rif_patch_2;
  kmem[0] = 0xB0;
  kmem[1] = 0x01;
  kmem[2] = 0xC3;

  // Patch debug setting errors
  kmem = (uint8_t *)debug_settings_error_patch_1;
  kmem[0] = 0x00;
  kmem[1] = 0x00;
  kmem[2] = 0x00;
  kmem[3] = 0x00;

  kmem = (uint8_t *)debug_settings_error_patch_2;
  kmem[0] = 0x00;
  kmem[1] = 0x00;
  kmem[2] = 0x00;
  kmem[3] = 0x00;

  // Enable mount for unprivileged user
  // kmem = (uint8_t *)mount_patch;
  // kmem[0] = 0xEB;
  // kmem[1] = 0x04;

  // Change directory depth limit from 9 to 64
  kmem = (uint8_t *)depth_limit_patch;
  kmem[0] = 0x40;

  // Restore write protection
  writeCr0(cr0);

  return 0;
}

#define KERNEL_BASE_FILE 0xFFFFFFFF82200000

static void get_memory_dump2(uintptr_t addr, void *out, uint64_t outsz)
{
  uint8_t *pout = (uint8_t *)out;
  uint8_t *paddr = (uint8_t *)addr;
  for (uint64_t o = 0; o < outsz; o++)
  {
    pout[o] = paddr[o];
  }
}

static uint64_t get_kernel_size(uint64_t kernel_base)
{
  uint16_t elf_header_size;       // ELF header size
  uint16_t elf_header_entry_size; // ELF header entry size
  uint16_t num_of_elf_entries;    // Number of entries in the ELF header

  get_memory_dump2(kernel_base + 0x34, &elf_header_size, sizeof(uint16_t));
  get_memory_dump2(kernel_base + 0x34 + sizeof(uint16_t), &elf_header_entry_size, sizeof(uint16_t));
  get_memory_dump2(kernel_base + 0x34 + (sizeof(uint16_t) * 2), &num_of_elf_entries, sizeof(uint16_t));

  // printf_debug("elf_header_size: %u bytes\n", elf_header_size);
  // printf_debug("elf_header_entry_size: %u bytes\n", elf_header_entry_size);
  // printf_debug("num_of_elf_entries: %u\n", num_of_elf_entries);

  uint64_t max = 0;
  for (int i = 0; i < num_of_elf_entries; i++)
  {
    uint64_t temp_memsz;
    uint64_t temp_vaddr;
    uint64_t temp_align;
    uint64_t temp_max;

    uint64_t memsz_offset = elf_header_size + (i * elf_header_entry_size) + 0x28;
    uint64_t vaddr_offset = elf_header_size + (i * elf_header_entry_size) + 0x10;
    uint64_t align_offset = elf_header_size + (i * elf_header_entry_size) + 0x30;
    get_memory_dump2(kernel_base + memsz_offset, &temp_memsz, sizeof(uint64_t));
    get_memory_dump2(kernel_base + vaddr_offset, &temp_vaddr, sizeof(uint64_t));
    get_memory_dump2(kernel_base + align_offset, &temp_align, sizeof(uint64_t));

    temp_vaddr -= kernel_base;
    temp_vaddr += KERNEL_BASE_FILE;

    temp_max = (temp_vaddr + temp_memsz + (temp_align - 1)) & ~(temp_align - 1);

    if (temp_max > max)
    {
      max = temp_max;
    }
  }

  return max - KERNEL_BASE_FILE;
}

static uint64_t *u64_Scan(const void *module, uint64_t sizeOfImage, uint64_t value)
{
  uint8_t *scanBytes = (uint8_t *)module;
  for (size_t i = 0; i < sizeOfImage; ++i)
  {
    uint64_t currentValue = *(uint64_t *)&scanBytes[i];
    if (currentValue == value)
    {
      return (uint64_t *)&scanBytes[i];
    }
  }
  return 0;
}

// Return 0 on success
// Return -1 on memory allocation error or unsupported firmware error
// Can also just give a memory error in the browser or panic the console on failure
int kpayload_install_payload(struct thread *td, struct kpayload_install_payload_args *args) {
  UNUSED(td);
  void *kernel_base;
  uint8_t *kernel_ptr;

  // Use "kmem" for all patches
  uint8_t *kmem;

  // Pointers to be assigned in build_kpayload macro
  void *kernel_pmap_store;
  uint8_t *pmap_protect_p_patch;
  uint8_t *payload_buffer;

  void (*pmap_protect)(void *pmap, uint64_t sva, uint64_t eva, uint8_t pr);

  uint16_t fw_version = args->kpayload_payload_info->fw_version;

  // NOTE: This is a C preprocessor macro
  build_kpayload(fw_version, install_macro);

  const uint64_t kptr = (uint64_t)kernel_ptr;
  const uint64_t kernelsz = get_kernel_size(kptr);
  if (!kptr || !kernelsz)
  {
    return -1;
  }
  const uint64_t SCE_RELA_tag = 0x6100002F;
  const uintptr_t *sce_reloc = u64_Scan(kernel_base, kernelsz, SCE_RELA_tag);
  // discard old value
  payload_buffer = 0;
  if (sce_reloc)
  {
    payload_buffer = (uint8_t *)(kptr + (sce_reloc[1] - KERNEL_BASE_FILE));
  }
  else
  {
    return -1;
  }
  if (!payload_buffer)
  {
    return -1;
  }

  uint8_t *payload_data = args->kpayload_payload_info->buffer;
  size_t payload_size = args->kpayload_payload_info->size;

  struct kpayload_payload_header *payload_header = (struct kpayload_payload_header *)payload_data;

  if (!payload_data || payload_size < sizeof(payload_header) || payload_header->signature != 0x5041594C4F414458ull) { // `payloadx`
    return -1;
  }

  // Disable write protection
  uint64_t cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);

  memset(payload_buffer, '\0', PAGE_SIZE);
  memcpy(payload_buffer, payload_data, payload_size);

  uint64_t sss = ((uint64_t)payload_buffer) & ~(uint64_t)(PAGE_SIZE - 1);
  uint64_t eee = ((uint64_t)payload_buffer + payload_size + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);

  kmem = (uint8_t *)pmap_protect_p_patch;
  kmem[0] = 0xEB;
  pmap_protect(kernel_pmap_store, sss, eee, 7);
  kmem[0] = 0x75;

  // Restore write protection
  writeCr0(cr0);

  int (*payload_entrypoint)(uint16_t);
  *((void **)&payload_entrypoint) = (void *)(&payload_buffer[payload_header->entrypoint_offset]);

  return payload_entrypoint(fw_version);
}

// Passes on the result of kpayload_patches
int install_patches() {
  struct kpayload_firmware_info kpayload_firmware_info;
  kpayload_firmware_info.fw_version = get_firmware();
  return kexec(&kpayload_patches, &kpayload_firmware_info);
}

// Passes on the result of kpayload_install_payload
int install_payload() {
  struct kpayload_payload_info kpayload_payload_info;
  kpayload_payload_info.fw_version = get_firmware();
  kpayload_payload_info.buffer = (uint8_t *)kpayload_bin;
  kpayload_payload_info.size = (size_t)kpayload_bin_len;

  return kexec(&kpayload_install_payload, &kpayload_payload_info);
}

// Return 0 on "success" including no file found
// Return -1 on error
int set_target_id(char *tid) {
  // The function input is from a controlled source and is already checked
  int hex;
  sscanf(tid, "%x", &hex);

  // Longest string for this buffer is 23 chars + 1 null term
  char buffer[0x100] = {0};
  int buffer_size = sizeof(buffer);
  switch (hex) {
  case 0x80:
    snprintf(buffer, buffer_size, "Diagnostic");
    break;
  case 0x81:
    snprintf(buffer, buffer_size, "Devkit");
    break;
  case 0x82:
    snprintf(buffer, buffer_size, "Testkit");
    break;
  case 0x83:
    snprintf(buffer, buffer_size, "Japan");
    break;
  case 0x84:
    snprintf(buffer, buffer_size, "USA");
    break;
  case 0x85:
    snprintf(buffer, buffer_size, "Europe");
    break;
  case 0x86:
    snprintf(buffer, buffer_size, "Korea");
    break;
  case 0x87:
    snprintf(buffer, buffer_size, "United Kingdom");
    break;
  case 0x88:
    snprintf(buffer, buffer_size, "Mexico");
    break;
  case 0x89:
    snprintf(buffer, buffer_size, "Australia & New Zealand");
    break;
  case 0x8A:
    snprintf(buffer, buffer_size, "South Asia");
    break;
  case 0x8B:
    snprintf(buffer, buffer_size, "Taiwan");
    break;
  case 0x8C:
    snprintf(buffer, buffer_size, "Russia");
    break;
  case 0x8D:
    snprintf(buffer, buffer_size, "China");
    break;
  case 0x8E:
    snprintf(buffer, buffer_size, "Hong Kong");
    break;
  case 0x8F:
    snprintf(buffer, buffer_size, "Brazil");
    break;
  case 0xA0:
    snprintf(buffer, buffer_size, "Kratos");
    break;
  default:
    printf_notification("Spoofing: UNKNOWN...\nCheck your `hen.ini` file");
    return -1;
  }

  if (spoof_target_id(hex) != 0) {
    printf_notification("ERROR: Unable to spoof target ID");
    return -1;
  }

  printf_notification("Spoofing: %s", buffer);
  return 0;
}

static void write_blob(const char* path, const void* blob, const size_t blobsz) {
  int fd = open(path, O_CREAT | O_RDWR, 0777);
  printf_debug("fd %s %d\n", path, fd);
  if (fd > 0) {
    write(fd, blob,blobsz);
    close(fd);
  } else {
    printf_notification("Failed to write %s!\nFile descriptor %d", path, fd);
  }
}

static void upload_prx_to_disk(void) {
  write_blob("/user/data/plugin_bootloader.prx", plugin_bootloader_prx, plugin_bootloader_prx_len);
  write_blob("/user/data/plugin_loader.prx", plugin_loader_prx, plugin_loader_prx_len);
  write_blob("/user/data/plugin_server.prx", plugin_server_prx, plugin_server_prx_len);
}

static void kill_proc(const char* proc) {
  if (!proc)
  {
    return;
  }
  const int party = findProcess(proc);
  printf_debug("%s %d\n", proc, party);
  if (party > 0) {
    const int k = kill(party, SIGKILL);
    printf_debug("sent SIGKILL(%d) to %s(%d)\n", k, proc, party);
  }
}


static void upload_ver(void) {
  write_blob("/user/data/ps4hen_version.txt", VERSION, sizeof(VERSION) - 1);
}

int _main(struct thread *td) {
  UNUSED(td);

  initKernel();
  initLibc();

#ifdef DEBUG_SOCKET
  initNetwork();
  DEBUG_SOCK = SckConnect(DEBUG_IP, DEBUG_PORT);
#endif

  // Jailbreak the process
  jailbreak();

  // Unmount update directory. From etaHEN
  if ((int)unmount("/update", 0x80000LL) < 0) {
    unmount("/update", 0);
  }

  // Apply all HEN kernel patches
  install_patches();
  mmap_patch();

  // Get config, if it exists
  int config_loaded = 0;
  configuration config;
  memset(&config, '\0', sizeof(config));
  config.disable_aslr = DEFAULT_DISABLE_ASLR;
  config.nobd_patches = DEFAULT_NOBD_PATCHES;
  if (file_exists("/mnt/usb0/hen.ini")) {
    if (cfg_parse("/mnt/usb0/hen.ini", config_handler, &config) < 0) {
      printf_notification("ERROR: Unable to load `/mnt/usb0/hen.ini`");
      // Restore defaults in case one of them changed for some reason...
      memset(&config, '\0', sizeof(config));
      config.disable_aslr = DEFAULT_DISABLE_ASLR;
      config.nobd_patches = DEFAULT_NOBD_PATCHES;
    } else {
      if (!file_compare("/mnt/usb0/hen.ini", "/data/hen.ini")) {
        unlink("/data/hen.ini");
        copy_file("/mnt/usb0/hen.ini", "/data/hen.ini");
      }
      config_loaded = 1;
    }
  } else if (file_exists("/data/hen.ini")) {
    if (cfg_parse("/data/hen.ini", config_handler, &config) < 0) {
      printf_notification("ERROR: Unable to load `/data/hen.ini`");
      // Restore defaults in case one of them changed for some reason...
      memset(&config, '\0', sizeof(config));
      config.disable_aslr = DEFAULT_DISABLE_ASLR;
      config.nobd_patches = DEFAULT_NOBD_PATCHES;
    } else {
      config_loaded = 1;
    }
  }

  if (config.disable_aslr) {
    disable_aslr();
    // Only show ASLR popup if config file is read
    if (config_loaded) {
      printf_notification("Userland ASLR disabled");
    }
  }

  if (config.nobd_patches) {
    no_bd_patch();
    printf_notification("NoBD patches enabled");
  }

  // Install and run kpayload
  install_payload();

  // Do this after the kpayload so if the user spoofs it doesn't effect checks in the kpayload
  if (config.target_id[0] != '\0') {
    set_target_id(config.target_id);
  }

  upload_ver();
  // TODO: Option to enable/disable
  upload_prx_to_disk();

  printf_notification("Welcome to HEN %s", VERSION);
  // for future use
  const bool kill_ui = true;
  const int sleep_sec = kill_ui ? 4 : 1;
  const int u_to_sec = 1000 * 1000;
  const char* proc = kill_ui ? "SceShellUI" : 0;
  if (kill_ui) {
    usleep(sleep_sec * u_to_sec);
    printf_notification("HEN will restart %s\n"
                        "in %d seconds...",
                        proc, sleep_sec);
  }
#ifdef DEBUG_SOCKET
  printf_debug("Closing socket...\n");
  SckClose(DEBUG_SOCK);
#endif

  usleep(sleep_sec * u_to_sec);
  // this was choosen because SceShellCore will try to restart this daemon if it crashes
  // or manually killed in this case
  kill_proc("ScePartyDaemon");
  kill_proc(proc);

  return 0;
}
