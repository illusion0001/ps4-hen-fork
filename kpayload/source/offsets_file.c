#include <stddef.h>

#include "sections.h"

// #include "offsets/474.h"
// #include "offsets/500.h"
// #include "offsets/501.h"
// #include "offsets/503.h"
// #include "offsets/505.h"
// #include "offsets/507.h"
// #include "offsets/550.h"
// #include "offsets/553.h"
// #include "offsets/555.h"
// #include "offsets/556.h"
// #include "offsets/600.h"
// #include "offsets/602.h"
// #include "offsets/620.h"
// #include "offsets/650.h"
// #include "offsets/651.h"
// #include "offsets/670.h"
// #include "offsets/671.h"
// #include "offsets/672.h"
// #include "offsets/700.h"
// #include "offsets/701.h"
// #include "offsets/702.h"
// #include "offsets/750.h"
// #include "offsets/751.h"
// #include "offsets/755.h"
// #include "offsets/800.h"
// #include "offsets/801.h"
// #include "offsets/803.h"
// #include "offsets/850.h"
// #include "offsets/852.h"
// #include "offsets/900.h"
// #include "offsets/903.h"
// #include "offsets/904.h"
// #include "offsets/950.h"
// #include "offsets/951.h"
// #include "offsets/960.h"
// #include "offsets/1000.h"
// #include "offsets/1001.h"
// #include "offsets/1050.h"
// #include "offsets/1070.h"
// #include "offsets/1071.h"
// #include "offsets/1100.h"
// #include "offsets/1102.h"
#include "offsets/1150.h"
// #include "offsets/1152.h"
// #include "offsets/1200.h"
// #include "offsets/1202.h"

struct fw_offsets_entry {
  uint16_t fw_version;
  const struct kpayload_offsets *offsets;
};

static const struct fw_offsets_entry offsets_table[] PAYLOAD_RDATA = {
  // { 474, &offsets_474 }
  // { 500, &offsets_500 },
  // { 501, &offsets_501 },
  // { 503, &offsets_503 },
  // { 505, &offsets_505 },
  // { 507, &offsets_507 },
  // { 550, &offsets_550 },
  // { 553, &offsets_553 },
  // { 555, &offsets_555 },
  // { 556, &offsets_556 },
  // { 600, &offsets_600 },
  // { 602, &offsets_602 },
  // { 620, &offsets_620 },
  // { 650, &offsets_650 },
  // { 651, &offsets_651 },
  // { 670, &offsets_670 },
  // { 671, &offsets_671 },
  // { 672, &offsets_672 },
  // { 700, &offsets_700 },
  // { 701, &offsets_701 },
  // { 702, &offsets_702 },
  // { 750, &offsets_750 },
  // { 751, &offsets_751 },
  // { 755, &offsets_755 },
  // { 800, &offsets_800 },
  // { 801, &offsets_801 },
  // { 803, &offsets_803 },
  // { 850, &offsets_850 },
  // { 852, &offsets_852 },
  // { 900, &offsets_900 },
  // { 903, &offsets_903 },
  // { 904, &offsets_904 },
  // { 950, &offsets_950 },
  // { 951, &offsets_951 },
  // { 960, &offsets_960 },
  // { 1000, &offsets_1000 },
  // { 1001, &offsets_1001 },
  // { 1050, &offsets_1050 },
  // { 1070, &offsets_1070 },
  // { 1071, &offsets_1071 },
  // { 1100, &offsets_1100 },
  // { 1102, &offsets_1102 },
  { 1150, &offsets_1150 },
  // { 1152, &offsets_1152 },
  // { 1200, &offsets_1200 },
  // { 1202, &offsets_1202 },
};

PAYLOAD_CODE const struct kpayload_offsets *get_offsets_for_fw(uint16_t fw_version) {
  for (size_t i = 0; i < sizeof(offsets_table) / sizeof(offsets_table[0]); ++i) {
    if (offsets_table[i].fw_version == fw_version) {
      return offsets_table[i].offsets;
    }
  }
  return NULL;
}
