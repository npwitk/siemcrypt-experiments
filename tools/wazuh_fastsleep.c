/* Preloaded into wazuh-analysisd (before libfaketime) by tools/wazuh_faketime_start.sh.
 *
 * analysisd's frequency/timeframe rules compare an event's time with a cached
 * `current_time` that a background thread refreshes once per sleep(1)
 * (w_log_rotate_thread, analysisd.c in Wazuh 4.8.2). When the replay jumps the faked
 * clock, the cache is up to one real second stale, which is hours of log time. This
 * shim shortens sleep(n) to n * 5 ms so the cache follows the faked clock within a few
 * milliseconds; tools/wazuh_replay.py waits for one tick after each clock jump.
 *
 * Build: gcc -shared -fPIC -O2 -o /var/ossec/lib/wazuh_fastsleep.so tools/wazuh_fastsleep.c
 */
#include <unistd.h>

unsigned int sleep(unsigned int seconds) {
    usleep(seconds * 5000u);
    return 0;
}
