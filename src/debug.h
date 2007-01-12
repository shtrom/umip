/* $Id: debug.h 1.7 05/12/07 16:09:18+02:00 vnuorval@tcs.hut.fi $ */

#ifdef MIP6_NDEBUG
#define NDEBUG 1
#define dbg(...)
#define cdbg(...)
#define dbg_buf(...)
#define BUG(x)
#define TRACE
#else
#define dbg(...) dbgprint(__FUNCTION__, __VA_ARGS__)
#define cdbg(...) dbgprint(NULL, __VA_ARGS__)
#define dbg_buf(data, len, ...) \
	debug_print_buffer(data, len, __FUNCTION__, __VA_ARGS__)

#define BUG(x) dbgprint("BUG", "%s %d %s\n", __FUNCTION__, __LINE__, x)
#define TRACE dbgprint(__FUNCTION__, "%d\n", __LINE__)

void dbgprint(const char *fname, const char *fmt, ...);

void debug_print_buffer(const void *data, const int len, 
			const char *fname, const char *fmt, ...);
#endif

#ifdef DEBUG_LOCKING

#define pthread_mutex_lock(x)\
do {dbg("pthread_mutex_lock(" #x ")\n");pthread_mutex_lock(x);} while(0)

#define pthread_mutex_unlock(x)\
do {pthread_mutex_unlock(x);dbg("pthread_mutex_unlock(" #x ")\n");} while(0)

#define pthread_rwlock_rdlock(x)\
do {dbg("pthread_rwlock_rdlock(" #x ")\n");pthread_rwlock_rdlock(x);} while(0)

#define pthread_rwlock_wrlock(x)\
do {dbg("pthread_rwlock_wrlock(" #x ")\n");pthread_rwlock_wrlock(x);} while(0)

#define pthread_rwlock_unlock(x)\
do {pthread_rwlock_unlock(x);dbg("pthread_rwlock_unlock(" #x ")\n");} while(0)

#define pthread_join(x, y)\
do {dbg("pthread_join(" #x ", " #y ")\n");pthread_join(x, y);} while(0)

#define pthread_cancel(x)\
do {dbg("pthread_cancel(" #x ")\n");pthread_cancel(x);} while(0)

#define pthread_cond_signal(x)\
do {dbg("pthread_cond_signal(" #x ")\n");pthread_cond_signal(x);} while(0)

#define pthread_cond_wait(x, y)\
do {dbg("pthread_cond_wait(" #x ", " #y ")\n");pthread_cond_wait(x, y);} while(0)

#define pthread_cond_timedwait(x, y, z)\
do {dbg("pthread_cond_wait(" #x ", " #y ", " #z ")\n");\
pthread_cond_timedwait(x, y, z);} while(0)

#endif

#include <assert.h>
