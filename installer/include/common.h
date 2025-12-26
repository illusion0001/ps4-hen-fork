#ifndef COMMON_H_
#define COMMON_H_

#include <types.h>

void write_blob(const char *path, const void *blob, const size_t blobsz);
void kill_proc(const char *proc);
void block_updates(void);

// redefined from `kpayload/include/freebsd_helper.h`
#define _countof(a) (sizeof(a) / sizeof(*(a)))

#endif
