// #define DEBUG_SOCKET
#define DEBUG_IP "192.168.2.2"
#define DEBUG_PORT 9023

#define VERSION "2.2.0 BETA"

#include "defines.h"
#include "offsets.h"

#include <ps4.h>

extern char kpayload[];
extern unsigned kpayload_size;

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

  int (*payload_entrypoint)();
  *((void **)&payload_entrypoint) = (void *)(&payload_buffer[payload_header->entrypoint_offset]);

  return payload_entrypoint();
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
  kpayload_payload_info.buffer = (uint8_t *)kpayload;
  kpayload_payload_info.size = (size_t)kpayload_size;

  return kexec(&kpayload_install_payload, &kpayload_payload_info);
}

// Return 0 on "success" including no file found
// Return -1 on error
int read_set_target_id() {
  int fd = open("/mnt/usb0/target.id", O_RDONLY, 0);
  if (fd < 0) {
    // No file found, assume they just don't have one on purpose
    return 0;
  }

  char hexstring[5] = {0};
  int bytes_read = read(fd, hexstring, 4);
  close(fd);
  if (bytes_read != 4) {
    printf_notification("ERROR: Malformed target.id:\n    Must be 4 bytes (e.g. 0x84)");
    return -1;
  }
  if (hexstring[0] != '0' || hexstring[1] != 'x' || !isxdigit(hexstring[2]) || !isxdigit(hexstring[3])) {
    printf_notification("ERROR: Malformed target.id:\n    Incorrect format, must be 0x?? (e.g. 0x84)");
    return -1;
  }

  int hex;
  sscanf(hexstring, "%x", &hex);

  // Longest string for this buffer is 23 chars + 1 null term
  char buffer[0x100] = {0};
  int buffer_size = sizeof(buffer);
  switch (hex) {
  case 0x80:
    snprintf_s(buffer, buffer_size, "Diagnostic");
    break;
  case 0x81:
    snprintf_s(buffer, buffer_size, "Devkit");
    break;
  case 0x82:
    snprintf_s(buffer, buffer_size, "Testkit");
    break;
  case 0x83:
    snprintf_s(buffer, buffer_size, "Japan");
    break;
  case 0x84:
    snprintf_s(buffer, buffer_size, "USA");
    break;
  case 0x85:
    snprintf_s(buffer, buffer_size, "Europe");
    break;
  case 0x86:
    snprintf_s(buffer, buffer_size, "Korea");
    break;
  case 0x87:
    snprintf_s(buffer, buffer_size, "United Kingdom");
    break;
  case 0x88:
    snprintf_s(buffer, buffer_size, "Mexico");
    break;
  case 0x89:
    snprintf_s(buffer, buffer_size, "Australia & New Zealand");
    break;
  case 0x8A:
    snprintf_s(buffer, buffer_size, "South Asia");
    break;
  case 0x8B:
    snprintf_s(buffer, buffer_size, "Taiwan");
    break;
  case 0x8C:
    snprintf_s(buffer, buffer_size, "Russia");
    break;
  case 0x8D:
    snprintf_s(buffer, buffer_size, "China");
    break;
  case 0x8E:
    snprintf_s(buffer, buffer_size, "Hong Kong");
    break;
  case 0x8F:
    snprintf_s(buffer, buffer_size, "Brazil");
    break;
  case 0xA0:
    snprintf_s(buffer, buffer_size, "Kratos");
    break;
  default:
    printf_notification("Spoofing: UNKNOWN...\nCheck your `/mnt/usb0/target.id` file");
    return -1;
  }

  if (spoof_target_id(hex) != 0) {
    printf_notification("ERROR: Unable to spoof target ID");
    return -1;
  }

  printf_notification("Spoofing: %s", buffer);
  return 0;
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

  // Apply all HEN kernel patches
  install_patches();
  mmap_patch();

  // Disable userland ASLR
  if (file_exists("/mnt/usb0/enable.aslr")) {
    disable_aslr();
  }

  // If `/mnt/usb0/no.bd` is found patch for the NoBD update method
  if (file_exists("/mnt/usb0/no.bd")) {
    no_bd_patch();
    printf_notification("NoBD patches enabled");
  }

  // Install and run kpayload
  install_payload();

  // Do this after the kpayload so if the user spoofs it doesn't effect checks in the kpayload
  // Spoofs the console's Target ID depending on the user's setup
  if (file_exists("/mnt/usb0/target.id")) {
    read_set_target_id();
  }

  printf_notification("Welcome to HEN %s", VERSION);

#ifdef DEBUG_SOCKET
  printf_debug("Closing socket...\n");
  SckClose(DEBUG_SOCK);
#endif

  return 0;
}
