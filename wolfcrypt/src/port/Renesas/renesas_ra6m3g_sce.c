
#ifdef WOLFSSL_RENESAS_RA6M3G
#include "wolfcrypt/port/renesas_ra6m3g_sce.h"

void ra6m3g_init(void) {
    HW_SCE_PowerOn();
}

#endif /* WOLFSSL_RENESAS_RA6M3G */
