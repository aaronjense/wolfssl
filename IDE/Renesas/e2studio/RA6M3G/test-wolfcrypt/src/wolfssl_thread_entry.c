#include <wolfssl/wolfcrypt/settings.h>
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/port/renesas_ra6m3g_sce.h"

void wolfssl_thread_entry(void* pvParameters)
{
    FSP_PARAMETER_NOT_USED (pvParameters);
    /* Benchmark output is displayed to Renesas Debug Virtual Console */
    initialise_monitor_handles();
    //ra6m3g_init();

    wolfcrypt_test(0);
    while(1);
}
