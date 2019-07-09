/*
 * Copyright (C) 2011-2019 Canonical
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Author: Colin Ian King <colin.king@canonical.com>
 *
 * Note: Code is optimised to reduce CPU overhead. There are some arcane
 * string scanning and string formatting specific functions to remove the
 * overhead of the use of sscanf and sprintf.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <float.h>
#include <fcntl.h>
#include <limits.h>
#include <ncurses.h>

#define APP_NAME		"cpustat"
#define TABLE_SIZE		(2411)		/* Should be a prime */
#define PID_HASH_SIZE		(11113)		/* Ideally a large prime */
#define OPT_QUIET		(0x00000001)
#define OPT_IGNORE_SELF		(0x00000002)
#define	OPT_CMD_SHORT		(0x00000004)
#define OPT_CMD_LONG		(0x00000008)
#define OPT_CMD_COMM		(0x00000010)
#define OPT_CMD_ALL		(OPT_CMD_SHORT | OPT_CMD_LONG | OPT_CMD_COMM)
#define OPT_DIRNAME_STRIP	(0x00000020)
#define OPT_TICKS_ALL		(0x00000040)
#define OPT_TOTAL		(0x00000080)
#define OPT_MATCH_PID		(0x00000100)
#define OPT_TIMESTAMP		(0x00000200)
#define OPT_GRAND_TOTAL		(0x00000400)
#define OPT_SAMPLES		(0x00000800)
#define OPT_DISTRIBUTION	(0x00001000)
#define OPT_EXTRA_STATS		(0x00002000)
#define OPT_TOP			(0x00004000)

/* Histogram specific constants */
#define MAX_DIVISIONS		(20)
#define DISTRIBUTION_WIDTH	(40)

#define SIZEOF_ARRAY(a)		(sizeof(a) / sizeof(a[0]))

#define _VER_(major, minor, patchlevel) \
	((major * 10000) + (minor * 100) + patchlevel)

#define FLOAT_TINY		(0.0000001)
#define FLOAT_CMP(a, b)		(fabs(a - b) < FLOAT_TINY)

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#if defined(__GNUC_PATCHLEVEL__)
#define NEED_GNUC(major, minor, patchlevel) \
	_VER_(major, minor, patchlevel) <= _VER_(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)
#else
#define NEED_GNUC(major, minor, patchlevel) \
	_VER_(major, minor, patchlevel) <= _VER_(__GNUC__, __GNUC_MINOR__, 0)
#endif
#else
#define NEED_GNUC(major, minor, patchlevel) (0)
#endif

#if defined(__GNUC__) && NEED_GNUC(4,6,0)
#define HOT __attribute__ ((hot))
#else
#define HOT
#endif

#if defined(__GNUC__) && !defined(__clang__) && NEED_GNUC(4,6,0)
#define OPTIMIZE3 __attribute__((optimize("-O3")))
#else
#define OPTIMIZE3
#endif

#if defined(__GNUC__)
#define LIKELY(x)	__builtin_expect((x),1)
#define UNLIKELY(x)	__builtin_expect((x),0)
#else
#define LIKELY(x)	(x)
#define UNLIKELY(x)	(x)
#endif

/* per process cpu information */
typedef struct cpu_info_t {
	struct cpu_info_t *hash_next;	/* Next cpu info in hash */
	struct cpu_info_t *list_next;	/* Next cpu info in list */
	char		*cmdline;	/* Full name of process cmdline */
	uint64_t	utotal;		/* Usr Space total CPU ticks */
	uint64_t	stotal;		/* Sys Space total CPU ticks */
	uint64_t	total;		/* Total number of CPU ticks */
	uint64_t	ticks;		/* Total life time in CPU ticks */
	pid_t		pid;		/* Process ID */
	int		processor;	/* Last CPU run on */
	bool		kernel_thread;	/* true if a kernel thread */
	char		state;		/* Run state */
	char 		comm[17];	/* Name of process/kernel task */
} cpu_info_t;

/* system wide CPU stats */
typedef struct {
	uint64_t	ctxt;		/* Context switches */
	uint64_t	irq;		/* IRQ count */
	uint64_t	softirq;	/* Soft IRQ count */
	uint64_t	processes;	/* Number of processes since boot */
	uint64_t	running;	/* Number of processes running */
	uint64_t	blocked;	/* Number of processes blocked */
} proc_stat_t;

/* CPU utilisation stats */
typedef struct cpu_stat {
	struct cpu_stat *next;		/* Next cpu stat in hash table */
	struct cpu_stat *sorted_usage_next;
					/* Next CPU stat in CPU usage list */
	cpu_info_t	*info;		/* CPU info */
	uint64_t	utime;		/* User time */
	uint64_t	stime;		/* System time */
	int64_t		delta;		/* Total Change in CPU ticks */
	int64_t		udelta;		/* Change in user time */
	int64_t		sdelta;		/* Change in system time */
	double		time;		/* Wall clock time */
	double		time_delta;	/* Wall clock time delta */
	bool		old;		/* Existing task, not a new one */
} cpu_stat_t;

/* sample delta item as an element of the sample_delta_list_t */
typedef struct sample_delta_item {
	struct sample_delta_item *next;	/* Next in the list */
	cpu_info_t	*info;		/* CPU info this refers to */
	int64_t		delta;		/* difference in CPU ticks */
	double		time_delta;	/* difference in time */
} sample_delta_item_t;

/* list of sample_delta_items */
typedef struct sample_delta_list {
	struct sample_delta_item *sample_delta_item_list;
	struct sample_delta_list *next;	/* next item in sample delta list */
	struct sample_delta_list *prev;	/* Previous in the list */
	double 		whence;		/* when the sample was taken */
} sample_delta_list_t;

/* hash of cmdline comm info */
typedef struct pid_info {
	struct pid_info *next;		/* next pid_info in list */
	struct timespec st_ctim;	/* time of process creation */
	char	*cmdline;		/* process command line */
	pid_t	pid;			/* process ID */
} pid_info_t;

typedef struct {
	double		threshold;	/* scaling threashold */
	double		scale;		/* scaling value */
	char 		*suffix;	/* Human Hz scale factor */
} cpu_freq_scale_t;

/* scaling factor */
typedef struct {
	const char ch;			/* Scaling suffix */
	const uint32_t base;		/* Base of part following . point */
	const uint64_t scale;		/* Amount to scale by */
} time_scale_t;

typedef struct {
	uint32_t hash;			/* Hash of /proc/stat field tag */
	uint16_t offset;		/* offset into proc_stat_t struct */
} proc_stat_fields_t;

/* ncurses mode or std tty mode display functions */
typedef struct {
	void (*df_setup)(void);
	void (*df_endwin)(void);
	void (*df_clear)(void);
	void (*df_refresh)(void);
	void (*df_winsize)(bool redo);
	void (*df_putstrnl)(char *str, int n);
	void (*df_linebreak)(void);
} display_funcs_t;

/* CPU frequency  scale suffixes */
static const cpu_freq_scale_t cpu_freq_scale[] = {
	{ 1e1,  1e0,  "Hz" },
	{ 1e4,  1e3,  "KHz" },
	{ 1e7,  1e6,  "MHz" },
	{ 1e10, 1e9,  "GHz" },
	{ 1e13, 1e12, "THz" },
	{ 1e16, 1e15, "PHz" },
};

/* seconds scale suffixes, secs, mins, hours, etc */
static const time_scale_t second_scales[] = {
	{ 's',	100, 1 },
	{ 'm',	 60, 60 },
	{ 'h',   60, 3600 },
	{ 'd',  100, 24 * 3600 },
	{ 'w',  100, 7 * 24 * 3600 },
	{ 'y',  100, 365 * 24 * 3600 },
	{ ' ',  100,  INT64_MAX },
};

static const proc_stat_fields_t fields[] = {
	{ 0x0000ca52, offsetof(proc_stat_t, irq) },	/* intr */
	{ 0x01fd11a1, offsetof(proc_stat_t, softirq) },	/* softirq */
	{ 0x0000d8b4, offsetof(proc_stat_t, ctxt) },	/* ctxt */
	{ 0xa114a557, offsetof(proc_stat_t, running) },	/* procs_running */
	{ 0xa1582f8c, offsetof(proc_stat_t, blocked) },	/* procs_blocked */
	{ 0x7fcb299b, offsetof(proc_stat_t, processes) },/* processes */
};

static cpu_stat_t *cpu_stat_free_list;	/* List of free'd cpu stats */
static cpu_info_t *cpu_info_hash[TABLE_SIZE];
					/* hash of cpu_info */
static cpu_info_t *cpu_info_list;	/* cache list of cpu_info */
static pid_info_t *pid_info_hash[PID_HASH_SIZE];
					/* Hash of cmdline info */
static size_t cpu_info_list_length;	/* cpu_info_list length */
static sample_delta_list_t *sample_delta_list_head;
static sample_delta_list_t *sample_delta_list_tail;
					/* samples, sorted by sample time */
static char *csv_results;		/* results in comma separated values */
static volatile bool stop_cpustat = false;	/* set by sighandler */
static double opt_threshold;		/* ignore samples with CPU usage deltas less than this */
static unsigned int opt_flags;		/* option flags */
static uint64_t clock_ticks;		/* number of clock ticks per second */
static pid_t opt_pid = -1;		/* PID to match against, -p option */

static bool resized;			/* window resized */
static int rows = 25;			/* tty size, rows */
static int cols = 80;			/* tty size, columns */
static int cury = 0;			/* current y curpos */
static int pid_max_digits;		/* maximum digits for PIDs */

static display_funcs_t df;		/* display functions */

/*
 *  Attempt to catch a range of signals so
 *  we can clean
 */
static const int signals[] = {
	/* POSIX.1-1990 */
#ifdef SIGHUP
	SIGHUP,
#endif
#ifdef SIGINT
	SIGINT,
#endif
#ifdef SIGQUIT
	SIGQUIT,
#endif
#ifdef SIGFPE
	SIGFPE,
#endif
#ifdef SIGTERM
	SIGTERM,
#endif
#ifdef SIGUSR1
	SIGUSR1,
#endif
#ifdef SIGUSR2
	SIGUSR2,
	/* POSIX.1-2001 */
#endif
#ifdef SIGXCPU
	SIGXCPU,
#endif
#ifdef SIGXFSZ
	SIGXFSZ,
#endif
	/* Linux various */
#ifdef SIGIOT
	SIGIOT,
#endif
#ifdef SIGSTKFLT
	SIGSTKFLT,
#endif
#ifdef SIGPWR
	SIGPWR,
#endif
#ifdef SIGINFO
	SIGINFO,
#endif
#ifdef SIGVTALRM
	SIGVTALRM,
#endif
	-1,
};

/*
 *  get_pid_max_digits()
 *	determine (or guess) maximum digits of pids
 */
static int get_pid_max_digits(void)
{
	ssize_t n;
	int digits, fd;
	const int default_digits = 6;
	const int min_digits = 5;
	char buf[32];

	digits = default_digits;
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0)
		goto ret;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n < 0)
		goto ret;

	buf[n] = '\0';
	digits = 0;
	while (buf[digits] >= '0' && buf[digits] <= '9')
		digits++;
	if (digits < min_digits)
		digits = min_digits;
ret:
	return digits;
}

/*
 *  handle_sigwinch()
 *      flag window resize on SIGWINCH
 */
static void handle_sigwinch(int sig)
{
	(void)sig;

	resized = true;
}

/*
 *  duration_round()
 *	round duration to nearest 1/100th second
 */
static inline double duration_round(const double duration)
{
        return floor((duration * 100.0) + 0.5) / 100.0;
}

/*
 *  putint()
 *	put a decimal value v into string str with max
 *	length of nbytes
 */
static int OPTIMIZE3 HOT putint(
	char * const str,
	int nbytes,
	int v,
	const bool zeropad)
{
        register char *ptr = str + nbytes;
	int ret = nbytes;
	char pad;

	*(ptr--) = '\0';
	while (--nbytes >= 0) {
		*(ptr--) = '0' + (v % 10);
		v /= 10;
		if (UNLIKELY(!v))
			break;
	}

	pad = zeropad ? '0' : ' ';
	while (--nbytes >= 0)
		*(ptr--) = pad;

	return ret;
}


/*
 *  putuint()
 *	put unsigned decimal value v into str
 *      with no leading spaces.
 */
static int OPTIMIZE3 HOT putuint(char *const str, unsigned int v)
{
	register char *ptr = str;
	register char *p1, *p2, *mid;

	do {
		*(ptr++) = '0' + (v % 10);
		v /= 10;
	} while (v);

	*ptr = '\0';

	/* and reverse */
	mid = str + ((ptr - str) >> 1);
	p1 = str;
	p2 = ptr - 1;
	while (p1 != mid) {
		register char c = *p1;
		*(p1++) = *p2;
		*(p2--) = c;
	}
	return ptr - str;
}

/*
 *  putdouble()
 *	put a double in %6.2 with trailing space
 */
static int OPTIMIZE3 HOT putdouble(
	char *str,
	const double val,
	const int base)
{
	const double v = val + 0.005; /* Round up */

	(void)putint(str, 3, (int)v, false);
	str[3] = '.';
	(void)putint(str + 4, 2, v * (double)base - (double)((int)v * base), true);
	str[2] = (str[2] == ' ') ? '0' : str[2];
	str[6] = ' ';
	str[7] = '\0';

	return 6;
}

/*
 *  putdouble_decpl
 *	put a double with decpl number of decimal places with trailing space, up to 4 decpl
 */
static int OPTIMIZE3 HOT putdouble_decpl(
	char * const str,
	double v,
	int decpl)
{
	char *ptr = str;
	static const double scales[] = {
		1.0,
		10.0,
		100.0,
		1000.0,
		10000.0
	};
	double scale;

	decpl = decpl > 4 ? 4 : decpl;
	scale = scales[decpl];

	v += 0.5 / scale;	/* Round up */
	ptr += putuint(ptr, (int)v);
	*(ptr++) = '.';
	ptr += putint(ptr, decpl, scale * v - (double)((int)v * scale), true);
	*ptr = '\0';

	return ptr - str;
}

/*
 *  putstr()
 *	append a string and return bytes added
 */
static int OPTIMIZE3 HOT putstr(char *dst, const int max, char *src)
{
	register int n = 0;

	while (LIKELY(*(dst++) = *(src++)) && LIKELY(n < max))
		n++;
	*dst = '\0';
	return n;
}

/*
 *   cpustat_top_setup
 *	setup display in top mode
 */
static void cpustat_top_setup(void)
{
	(void)initscr();
	(void)cbreak();
	(void)noecho();
	(void)nodelay(stdscr, 1);
	(void)keypad(stdscr, 1);
	(void)curs_set(0);
}

/*
 *  cpustat_generic_winsize()
 *	get tty size in top mode
 */
static void cpustat_generic_winsize(const bool redo)
{
	if (redo) {
		struct winsize ws;

		if (LIKELY(ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)) {
			rows = ws.ws_row;
			cols = ws.ws_col;
		} else {
			rows = 25;
			cols = 80;
		}
	}
}

static void cpustat_top_winsize(const bool redo)
{
	(void)redo;

	cpustat_generic_winsize(true);
	(void)resizeterm(rows, cols);
}

/*
 *  cpustat_noop()
 *	no-operation void handler
 */
static void cpustat_noop(void)
{
}


/*
 *  cpustat_top_endwin()
 *	call endwin in top mode
 */
static void cpustat_top_endwin(void)
{
	df.df_winsize(true);
	(void)resizeterm(rows, cols);
	(void)refresh();
	resized = false;
	(void)clear();
	(void)endwin();
}

/*
 * cpustat_top_clear()
 *	clear screen in top mode
 */
static inline void cpustat_top_clear(void)
{
	(void)clear();
}

/*
 *  cpustat_top_refresh()
 *	refresh screen in top mode
 */
static inline void cpustat_top_refresh(void)
{
	(void)refresh();
}

/*
 *  cpustat_top_putstrnl()
 * 	cpustat put string in top mode with newline
 *	(or not if there is potential for line wrap)
 */
static void cpustat_top_putstrnl(char * const str, const int n)
{
	if (UNLIKELY(cury >= rows))
		return;

	if (UNLIKELY(n > cols)) {
		str[cols] = '\0';
	} else {
		str[n] = '\n';
		str[n + 1] = '\0';
	}

	cury++;
	(void)addstr(str);
}

/*
 *  cpustat_normal_putstr(()
 * 	cpustat put string in normal mode with newline
 */
static void cpustat_normal_putstrnl(char * const str, int n)
{
	if (UNLIKELY(n > cols))
		n = cols;

	str[n] = '\n';
	str[n + 1] = '\0';

	(void)fputs(str, stdout);
}

/*
 *  cpustat_normal_linebreak()
 *	put a line break between output
 */
static void cpustat_normal_linebreak(void)
{
	(void)putc('\n', stdout);
}

/* 'top' mode display functions */
static const display_funcs_t df_top = {
	cpustat_top_setup,
	cpustat_top_endwin,
	cpustat_top_clear,
	cpustat_top_refresh,
	cpustat_top_winsize,
	cpustat_top_putstrnl,
	cpustat_noop,
};

/* normal tty mode display functions */
static const display_funcs_t df_normal = {
	cpustat_noop,
	cpustat_noop,
	cpustat_noop,
	cpustat_noop,
	cpustat_generic_winsize,
	cpustat_normal_putstrnl,
	cpustat_normal_linebreak,
};

/*
 *  strtouint64()
 *	fast string to uint64, is ~33% faster than GNU libc
 *	no white space pre-skip or -ve handling
 */
static uint64_t OPTIMIZE3 HOT strtouint64(char *str, char **endptr)
{
	register uint64_t v = 0;

	for (;;) {
		register unsigned int digit = *str - '0';

		if (UNLIKELY(digit > 9))
			break;
		if (UNLIKELY(v >= 1844674407370955161ULL))
			goto do_overflow;
		v *= 10;
		v += digit;
		str++;
	}
	*endptr = str;
	return v;
do_overflow:
	errno = ERANGE;
	return ~0;

}

/*
 *  strtouint32()
 *	fast string to uint32, is ~33% faster than GNU libc
 *	no white space pre-skip or -ve handling
 */
static uint32_t OPTIMIZE3 HOT strtouint32(char *str, char **endptr)
{
	register uint64_t v = 0;

	for (;;) {
		register unsigned int digit = *str - '0';

		if (UNLIKELY(digit > 9))
			break;
		if (UNLIKELY(v >= 429496729))
			goto do_overflow;
		v *= 10;
		v += digit;
		str++;
	}
	*endptr = str;
	return v;
do_overflow:
	errno = ERANGE;
	return ~0;

}

/*
 *  get_ticks()
 *	get ticks
 */
static inline uint64_t OPTIMIZE3 HOT get_ticks(void)
{
	return (opt_flags & OPT_TICKS_ALL) ?
		clock_ticks * (uint64_t)sysconf(_SC_NPROCESSORS_ONLN) :
		clock_ticks;
}

/*
 *  secs_to_str()
 *	report seconds in different units.
 */
static char *secs_to_str(const double secs)
{
	static char buf[16];
	size_t i;
	double s = secs;

	for (i = 0; i < 5; i++) {
		if (s <= second_scales[i + 1].scale)
			break;
	}
	s /= second_scales[i].scale;

	(void)putdouble(buf, s, second_scales[i].base);
	buf[6] = second_scales[i].ch;

	return buf;
}

/*
 *  get_tm()
 *	fetch tm, will set fields to zero if can't get
 */
static void get_tm(const double time_now, struct tm * const tm)
{
	time_t now = (time_t)time_now;

	if (UNLIKELY((now == ((time_t) -1)))) {
		memset(tm, 0, sizeof(*tm));
	} else {
		(void)localtime_r(&now, tm);
	}
}

/*
 *  timeval_to_double
 *	timeval to a double (in seconds)
 */
static inline double timeval_to_double(const struct timeval *const tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  double_to_timeval
 *	seconds in double to timeval
 */
static inline void double_to_timeval(
	const double val,
	struct timeval * const tv)
{
	tv->tv_sec = val;
	tv->tv_usec = (val - (time_t)val) * 1000000.0;
}

/*
 *  gettime_to_double()
 *	get time as a double
 */
static double gettime_to_double(void)
{
	struct timeval tv;

        if (UNLIKELY(gettimeofday(&tv, NULL) < 0)) {
                (void)fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
                        errno, strerror(errno));
                exit(EXIT_FAILURE);
        }
        return timeval_to_double(&tv);
}

/*
 *  handle_sig()
 *      catch signal and flag a stop
 */
static void handle_sig(int dummy)
{
	(void)dummy;

	stop_cpustat = true;
}

/*
 *  count_bits()
 */
#if defined(__GNUC__)
/*
 *  use GCC built-in
 */
static inline unsigned int count_bits(const unsigned int val)
{
	return __builtin_popcount(val);
}
#else
/*
 *  count bits set, from C Programming Language 2nd Ed
 */
static inline unsigned int OPTIMIZE3 HOT count_bits(const unsigned int val)
{
	register unsigned int c, n = val;

	for (c = 0; n; c++)
		n &= n - 1;

	return c;
}
#endif

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *get_pid_cmdline(const pid_t pid)
{
	static char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;
	pid_info_t *info;
	int h = pid % PID_HASH_SIZE;
	char path[PATH_MAX];
	struct stat statbuf;
	bool statok = false;

	ptr = path;
	ptr += putstr(ptr, 6, "/proc/");
	ptr += putuint(ptr, pid);
	(void)putstr(ptr, 8, "/cmdline");
	ptr = NULL;

	if (UNLIKELY((fd = open(path, O_RDONLY)) < 0))
		return NULL;

	if (LIKELY(fstat(fd, &statbuf) == 0)) {
		statok = true;
		for (info = pid_info_hash[h]; info; info = info->next) {
			if (info->pid == pid) {
				if (statbuf.st_ctim.tv_sec >
				    info->st_ctim.tv_sec)
					break;
				(void)close(fd);
				return info->cmdline;
			}
		}
	}
	ret = read(fd, buffer, sizeof(buffer));
	(void)close(fd);
	if (ret <= 0)
		goto no_cmd;

	if (UNLIKELY(ret >= (ssize_t)sizeof(buffer)))
		ret = sizeof(buffer) - 1;
	buffer[ret] = '\0';

	/*
	 *  OPT_CMD_LONG option we get the full cmdline args
	 */
	if (opt_flags & OPT_CMD_LONG) {
		for (ptr = buffer; ptr < buffer + ret - 1; ptr++) {
			if (*ptr == '\0')
				*ptr = ' ';
		}
		*ptr = '\0';
	}
	/*
	 *  OPT_CMD_SHORT option we discard anything after a space
	 */
	if (opt_flags & OPT_CMD_SHORT) {
		for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
			if (*ptr == ' ')
				*ptr = '\0';
		}
	}

	if (opt_flags & OPT_DIRNAME_STRIP)
		ptr = basename(buffer);
	else
		ptr = buffer;

no_cmd:
	if (statok) {
		bool new_info = false;
		/*
		 * We may be re-using a stale old PID, or we may need
		 * a new info struct
		 */
		if (!info) {
			info = malloc(sizeof(*info));
			new_info = true;
		}

		/*
		 *  Don't worry if we can't allocate cache info
		 *  as we can fetch it next time if need be
		 */
		if (LIKELY((info != NULL))) {
			info->pid = pid;
			info->cmdline = ptr;
			info->st_ctim = statbuf.st_ctim;

			/* Only append to hash list if new */
			if (new_info) {
				info->next = pid_info_hash[h];
				pid_info_hash[h] = info;
			}
		}
	}
	return ptr;
}

/*
 *  pid_info_hash_free()
 *	free pid_info hash table
 *
 */
static void pid_info_hash_free(void)
{
	size_t i;

	for (i = 0; i < PID_HASH_SIZE; i++) {
		pid_info_t *info = pid_info_hash[i];

		while (info) {
			pid_info_t *next = info->next;

			free(info);
			info = next;
		}
	}
}

/*
 *  samples_free()
 *	free collected samples
 */
static void samples_free(void)
{
	sample_delta_list_t *sdl = sample_delta_list_head;

	while (sdl) {
		sample_delta_list_t *sdl_next = sdl->next;
		sample_delta_item_t *sdi = sdl->sample_delta_item_list;

		while (sdi) {
			sample_delta_item_t *sdi_next = sdi->next;
			free(sdi);
			sdi = sdi_next;
		}
		free(sdl);
		sdl = sdl_next;
	}
}

/*
 *  sample_add()
 *	add a cpu_stat's delta and info field to a list at time position whence
 */
static void OPTIMIZE3 HOT sample_add(
	const cpu_stat_t *const cpu_stat,
	const double whence)
{
	bool	found = false;
	sample_delta_list_t *sdl;
	sample_delta_item_t *sdi;

	for (sdl = sample_delta_list_tail; sdl; sdl = sdl->prev) {
		if (FLOAT_CMP(sdl->whence, whence)) {
			found = true;
			break;
		}
		if (sdl->whence < whence)
			break;
	}

	/*
	 * New time period, need new sdl, we assume it goes at the end of the
	 * list since time is assumed to be increasing
	 */
	if (!found) {
		if (UNLIKELY((sdl = malloc(sizeof(*sdl))) == NULL)) {
			(void)fprintf(stderr, "Cannot allocate sample delta list\n");
			exit(EXIT_FAILURE);
		}
		sdl->next = NULL;
		sdl->whence = whence;
		sdl->sample_delta_item_list = NULL;
		if (sample_delta_list_tail)
			sample_delta_list_tail->next = sdl;
		else
			sample_delta_list_head = sdl;

		sdl->prev = sample_delta_list_tail;
		sample_delta_list_tail = sdl;
	}

	/* Now append the sdi onto the list */
	if (UNLIKELY((sdi = malloc(sizeof(*sdi))) == NULL)) {
		(void)fprintf(stderr, "Cannot allocate sample delta item\n");
		exit(EXIT_FAILURE);
	}
	sdi->next = sdl->sample_delta_item_list;
	sdi->info = cpu_stat->info;
	sdi->delta = cpu_stat->delta;
	sdi->time_delta = cpu_stat->time_delta;

	sdl->sample_delta_item_list = sdi;
}

/*
 *  sample_find()
 *	scan through a sample_delta_list for cpu info, return NULL if not found
 */
static inline OPTIMIZE3 HOT sample_delta_item_t *sample_find(
	const sample_delta_list_t *const sdl,
	const cpu_info_t *const info)
{
	sample_delta_item_t *sdi;

	for (sdi = sdl->sample_delta_item_list; sdi; sdi = sdi->next) {
		if (sdi->info == info)
			return sdi;
	}
	return NULL;
}

/*
 * info_compare_total()
 *	used by qsort to sort array in CPU consumed ticks total order
 */
static int info_compare_total(const void *const item1, const void *const item2)
{
	cpu_info_t *const *info1 = (cpu_info_t *const *)item1;
	cpu_info_t *const *info2 = (cpu_info_t *const *)item2;

	if ((*info2)->total == (*info1)->total)
		return 0;

	return ((*info2)->total > (*info1)->total) ? 1 : -1;
}

/*
 *  info_banner_dump()
 *	dump banner for per_info stats
 */
static void info_banner_dump(const double time_now)
{
	static char str[256];
	static char *hdrptr;
	char *ptr;

	if (!hdrptr) {
		int i;

		hdrptr = str;
		(void)strncpy(hdrptr, "  %CPU   %USR   %SYS   ", sizeof(str));
		hdrptr += 23;
		for (i = 0; i < pid_max_digits - 5; i++, hdrptr++)
			*hdrptr = ' ';
		(void)strncpy(hdrptr, "PID S  CPU    Time Task",
			sizeof(str) - (3 + pid_max_digits));
		hdrptr += 23;
	}
	ptr = hdrptr;

	if (UNLIKELY(opt_flags & OPT_TIMESTAMP)) {
		struct tm tm;

		get_tm(time_now, &tm);
		(void)strncpy(ptr, "  (", 3);
		ptr += 3;
		ptr += putint(ptr, 2, tm.tm_hour, true);
		*ptr = ':';
		ptr++;
		ptr += putint(ptr, 2, tm.tm_min, true);
		*ptr = ':';
		ptr++;
		ptr += putint(ptr, 2, tm.tm_sec, true);
		*ptr = ')';
		ptr++;
	}
	*ptr = '\0';
	df.df_putstrnl(str, ptr - str);
}

/*
 *  info_dump()
 *	dump per cpu_info stats
 */
static void info_dump(
	const uint64_t uticks,
	const uint64_t sticks,
	const uint64_t total_ticks,
	const cpu_info_t *info,
	double *const u_total,
	double *const s_total)
{
	char buffer[512], *ptr = buffer;

	const double cpu_u_usage =
		total_ticks == 0 ? 0.0 : 100.0 * (double)uticks / total_ticks;
	const double cpu_s_usage =
		total_ticks == 0 ? 0.0 : 100.0 * (double)sticks / total_ticks;
	double cpu_time = ((double)(info->ticks)) / (double)clock_ticks;

	*u_total += cpu_u_usage;
	*s_total += cpu_s_usage;

	ptr += putdouble(ptr, cpu_u_usage + cpu_s_usage, 100);
	*(ptr++) = ' ';
	ptr += putdouble(ptr, cpu_u_usage, 100);
	*(ptr++) = ' ';
	ptr += putdouble(ptr, cpu_s_usage, 100);
	*(ptr++) = ' ';
	ptr += putint(ptr, pid_max_digits, info->pid, false);
	*(ptr++) = ' ';
	*(ptr++) = info->state;
	*(ptr++) = ' ';
	ptr += putint(ptr, 4, info->processor, false);
	*(ptr++) = ' ';
	ptr += putstr(ptr, 20, secs_to_str(cpu_time));
	*(ptr++) = ' ';
	if (info->kernel_thread)
		*(ptr++) = '[';
	ptr += putstr(ptr, 128, info->cmdline);
	if (info->kernel_thread)
		*(ptr++) = ']';
	*ptr = '\0';

	df.df_putstrnl(buffer, ptr - buffer);
}

/*
 *  info_total_dump()
 *	dump out totals of total, system and user times
 */
static inline void info_total_dump(
	const double u_total,
	const double s_total)
{
	if (UNLIKELY(opt_flags & OPT_TOTAL)) {
		char buffer[256], *ptr = buffer;

		ptr += putdouble(ptr, u_total + s_total, 100);
		*(ptr++) = ' ';
		ptr += putdouble(ptr, u_total, 100);
		*(ptr++) = ' ';
		ptr += putdouble(ptr, s_total, 100);
		*(ptr++) = ' ';
		ptr += putstr(ptr, 5, "Total");
		df.df_putstrnl(buffer, ptr - buffer);
	}
}

/*
 *  samples_dump()
 *	dump out samples to file
 */
static void samples_dump(
	const char *const filename,	/* file to dump samples */
	const double duration,		/* duration in seconds */
	const double time_now,		/* time right now */
	const uint64_t nr_ticks,	/* number of ticks per sec */
	const uint64_t total_ticks,	/* total clock ticks */
	const uint32_t samples)		/* number of samples */
{
	sample_delta_list_t	*sdl;
	cpu_info_t **sorted_cpu_infos;
	cpu_info_t *cpu_info;
	size_t i = 0, n;
	FILE *fp;
	double first_time = -1.0;

	if (UNLIKELY((sorted_cpu_infos =
	     calloc(cpu_info_list_length, sizeof(*sorted_cpu_infos))) == NULL)) {
		(void)fprintf(stderr,
			"Cannot allocate buffer for sorting cpu_infos\n");
		exit(EXIT_FAILURE);
	}

	/* Just want the CPUs with some non-zero total */
	for (n = 0, cpu_info = cpu_info_list; cpu_info;
	     cpu_info = cpu_info->list_next) {
		if (LIKELY((cpu_info->total > 0)))
			sorted_cpu_infos[n++] = cpu_info;
	}

	qsort(sorted_cpu_infos, n, sizeof(cpu_info_t *), info_compare_total);

	if (opt_flags & OPT_GRAND_TOTAL) {
		double cpu_u_total = 0.0, cpu_s_total = 0.0;

		(void)printf("Grand Total (from %" PRIu32 " samples, %.1f seconds):\n",
			samples, duration);
		info_banner_dump(time_now);
		for (i = 0; i < n; i++) {
			info_dump(sorted_cpu_infos[i]->utotal,
				sorted_cpu_infos[i]->stotal,
				total_ticks, sorted_cpu_infos[i],
				&cpu_u_total, &cpu_s_total);
		}
		info_total_dump(cpu_u_total, cpu_s_total);
		(void)putchar('\n');
	}

	if (!filename) {
		free(sorted_cpu_infos);
		return;
	}

	if ((fp = fopen(filename, "w")) == NULL) {
		(void)fprintf(stderr, "Cannot write to file %s\n", filename);
		free(sorted_cpu_infos);
		return;
	}
	(void)fprintf(fp, "Task:%s", (opt_flags & OPT_TIMESTAMP) ? "," : "");
	for (i = 0; i < n; i++)
		(void)fprintf(fp, ",%s (%d)", sorted_cpu_infos[i]->comm,
			sorted_cpu_infos[i]->pid);
	(void)fprintf(fp, "\n");

	(void)fprintf(fp, "Ticks:%s", (opt_flags & OPT_TIMESTAMP) ? "," : "");
	for (i = 0; i < n; i++)
		(void)fprintf(fp, ",%" PRIu64, sorted_cpu_infos[i]->total);
	(void)fprintf(fp, "\n");

	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		if (first_time < 0)
			first_time = sdl->whence;

		(void)fprintf(fp, "%f", duration_round(sdl->whence - first_time));
		if (opt_flags & OPT_TIMESTAMP) {
			struct tm tm;

			get_tm(sdl->whence, &tm);
			(void)fprintf(fp, ",%02d:%02d:%02d",
				tm.tm_hour, tm.tm_min, tm.tm_sec);
		}

		/* Scan in CPU info order to be consistent for all sdl rows */
		for (i = 0; i < n; i++) {
			sample_delta_item_t *sdi =
				sample_find(sdl, sorted_cpu_infos[i]);
			if (sdi) {
				double tmp_duration =
					duration_round(sdi->time_delta);
				(void)fprintf(fp,",%f",
					(tmp_duration < 0.01) ? 0.0 :
					100.0 * (double)sdi->delta /
					(duration * (double)nr_ticks));
			} else
				(void)fprintf(fp,", ");
		}
		(void)fprintf(fp, "\n");
	}

	free(sorted_cpu_infos);
	(void)fclose(fp);
}

/*
 *  max_processors()
 *	Determine number of CPUs used
 */
static inline int max_processors(void)
{
	int cpu_max = 0;

	cpu_info_t *cpu_info;

	for (cpu_info = cpu_info_list; cpu_info;
	     cpu_info = cpu_info->list_next)
		if (cpu_info->processor > cpu_max)
			cpu_max = cpu_info->processor;

	return cpu_max + 1;
}

/*
 *  cpu_distribution()
 *	CPU distribution()
 */
static void cpu_distribution(
	const uint64_t total_ticks)
{
	cpu_info_t *cpu_info;
	int i, cpu_max = max_processors();
	uint64_t utotal[cpu_max], stotal[cpu_max];

	if (!total_ticks) {
		(void)printf("Cannot calculate distribution of CPU utilisation, "
			"(zero clock tick)\n");
		return;
	}

	(void)memset(utotal, 0, sizeof(utotal));
	(void)memset(stotal, 0, sizeof(stotal));

	for (cpu_info = cpu_info_list; cpu_info;
	     cpu_info = cpu_info->list_next) {
		int cpu = cpu_info->processor;
		utotal[cpu] += cpu_info->utotal;
		stotal[cpu] += cpu_info->stotal;
	}
	(void)printf("Distribution of CPU utilisation (per CPU):\n");
	(void)printf(" CPU#   USR%%   SYS%%\n");
	for (i = 0; i < cpu_max; i++)
		(void)printf("%5d %6.2f %6.2f\n",
			i,
			100.0 * (double)utotal[i] / (double)total_ticks,
			100.0 * (double)stotal[i] / (double)total_ticks);
}


/*
 *  samples_distribution()
 *	show distribution of CPU utilisation
 */
static void samples_distribution(const uint64_t nr_ticks)
{
	sample_delta_list_t *sdl;
	unsigned int bucket[MAX_DIVISIONS], max_bucket = 0, valid = 0, i, total = 0;
	double min = DBL_MAX, max = -DBL_MAX, division, prev;
	const double scale = 100.0 / (double)nr_ticks;

	(void)memset(bucket, 0, sizeof(bucket));

	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		sample_delta_item_t *sdi;

		for (sdi = sdl->sample_delta_item_list; sdi; sdi = sdi->next) {
			double val = scale * (double)sdi->delta;
			if (val > max)
				max = val;
			if (val < min)
				min = val;
			valid++;
		}
	}

	if (valid <= 1) {
		(void)printf("Too few samples, cannot compute distribution\n");
		return;
	}

	if (max - min < 0.01) {
		(void)printf("Range is too small, cannot compute distribution\n");
		return;
	}
	division = ((max * 1.000001) - min) / (MAX_DIVISIONS);
	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		sample_delta_item_t *sdi;

		for (sdi = sdl->sample_delta_item_list; sdi; sdi = sdi->next) {
			double val = 100.0 * (double)sdi->delta
				/ (double)nr_ticks;
			int v = floor(val - min) / division;
			v = v > MAX_DIVISIONS - 1 ? MAX_DIVISIONS -1 : v;
			bucket[v]++;
			total++;
			if (max_bucket < bucket[v])
				max_bucket = bucket[v];
		}
	}
	(void)printf("Distribution of CPU utilisation (per Task):\n");
	(void)printf("%% CPU Utilisation   Count   (%%)\n");
	for (prev = min, i = 0; i < MAX_DIVISIONS; i++, prev += division) {
		(void)printf("%6.2f - %6.2f  %8u %6.2f\n",
			prev, prev + division - 0.001,
			bucket[i],
			100.0 * (double)bucket[i] / (double)total);
	}
	putc('\n', stdout);
}

/*
 *  cpu_info_find()
 *	try to find existing cpu info in cache, and to the cache
 *	if it is new.
 */
static cpu_info_t OPTIMIZE3 HOT *cpu_info_find(
	const cpu_info_t *const new_info,
	const uint32_t hash)
{
	cpu_info_t *info;
	const char *comm = new_info->comm;
	const pid_t pid = new_info->pid;

	for (info = cpu_info_hash[hash]; info; info = info->hash_next) {
		if ((pid == info->pid) && (strcmp(comm, info->comm) == 0))
			return info;
	}

	if (UNLIKELY((info = malloc(sizeof(*info))) == NULL)) {
		(void)fprintf(stderr, "Cannot allocate CPU info\n");
		exit(EXIT_FAILURE);
	}
	(void)memcpy(info, new_info, sizeof(*info));

	if ((new_info->cmdline == NULL) || (opt_flags & OPT_CMD_COMM)) {
		info->cmdline = info->comm;
	} else {
		if (UNLIKELY((info->cmdline = strdup(new_info->cmdline)) == NULL)) {
			(void)fprintf(stderr, "Cannot allocate CPU cmdline field info\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Does not exist in list, append it */
	info->list_next = cpu_info_list;
	cpu_info_list = info;
	cpu_info_list_length++;

	info->hash_next = cpu_info_hash[hash];
	cpu_info_hash[hash] = info;
	return info;
}

/*
 *  cpu_info_free()
 *	free cpu_info and it's elements
 */
static void cpu_info_free(void *const data)
{
	cpu_info_t *info = (cpu_info_t*)data;

	if (info->cmdline != info->comm)
		free(info->cmdline);
	free(info);
}

/*
 *  cpu_info_list_free
 *	free up all unique cpu infos
 */
static void cpu_info_list_free(void)
{
	cpu_info_t *cpu_info = cpu_info_list;

	while (cpu_info) {
		cpu_info_t *next = cpu_info->list_next;
		cpu_info_free(cpu_info);

		cpu_info = next;
	}
}

/*
 *  cpu_stat_list_free
 *	free up cpu stat info from the free list
 */
static void cpu_stat_list_free(void)
{
	cpu_stat_t *cs = cpu_stat_free_list;

	while (cs) {
		cpu_stat_t *next = cs->next;
		free(cs);
		cs = next;
	}
}

/*
 *  hash_djb2a()
 *	Hash a string, from Dan Bernstein comp.lang.c (xor version)
 */
static uint32_t OPTIMIZE3 HOT hash_djb2a(const pid_t pid, const char *str)
{
	register uint32_t hash = 5381 + pid;
	register int c;

	while ((c = *str++)) {
		/* (hash * 33) ^ c */
		hash = ((hash << 5) + hash) ^ c;
	}
	return hash % TABLE_SIZE;
}

/*
 *  cpu_stat_free_contents()
 *	Free CPU info from a hash table
 */
static void cpu_stat_free_contents(
	cpu_stat_t *cpu_stats[])	/* CPU stat hash table */
{
	size_t i;

	for (i = 0; i < TABLE_SIZE; i++) {
		cpu_stat_t *cs = cpu_stats[i];

		while (cs) {
			cpu_stat_t *next = cs->next;

			/* Shove it onto the free list */
			cs->next = cpu_stat_free_list;
			cpu_stat_free_list = cs;

			cs = next;
		}
		cpu_stats[i] = NULL;
	}
}

/*
 *  cpu_stat_add()
 *	add pid stats to a hash table if it is new, otherwise just
 *	accumulate the tick count.
 */
static void OPTIMIZE3 HOT cpu_stat_add(
	cpu_stat_t *cpu_stats[],	/* CPU stat hash table */
	cpu_info_t *info,		/* paritially complete cpu info */
	const double time_now,		/* time sample was taken */
	const uint64_t utime,		/* user time in ticks */
	const uint64_t stime)		/* system time in ticks */
{
	cpu_stat_t *cs, *cs_new;
	uint32_t h;
	const char *comm = info->comm;
	const pid_t pid = info->pid;

	h = hash_djb2a(pid, comm);

	for (cs = cpu_stats[h]; cs; cs = cs->next) {
		if ((pid == cs->info->pid) && (strcmp(cs->info->comm, comm) == 0)) {
			cs->utime += utime;
			cs->stime += stime;
			cs->info->state = info->state;
			cs->info->processor = info->processor;
			return;
		}
	}
	/* Not found, it is new! */
	if (cpu_stat_free_list) {
		/* Re-use one from the free list */
		cs_new = cpu_stat_free_list;
		cpu_stat_free_list = cs_new->next;
	} else {
		if (UNLIKELY((cs_new = malloc(sizeof(*cs_new))) == NULL)) {
			(void)fprintf(stderr,
				"Out of memory allocating a cpu stat\n");
			exit(1);
		}
	}

	info->cmdline = get_pid_cmdline(pid);
	info->kernel_thread = (info->cmdline == NULL);

	cs_new->utime = utime;
	cs_new->stime = stime;
	cs_new->info = cpu_info_find(info, h);
	cs_new->time = time_now;
	cs_new->time_delta = 0.0;
	cs_new->old = false;
	cs_new->next = cpu_stats[h];
	cs_new->sorted_usage_next = NULL;

	cpu_stats[h] = cs_new;
}

/*
 *  cpu_stat_find()
 *	find a CPU stat (needle) in a CPU stat hash table (haystack)
 */
static cpu_stat_t OPTIMIZE3 HOT *cpu_stat_find(
	cpu_stat_t *const haystack[],		/* CPU stat hash table */
	const cpu_stat_t *const needle)		/* CPU stat to find */
{
	cpu_stat_t *ts;
	const char *comm = needle->info->comm;
	const pid_t pid = needle->info->pid;

	for (ts = haystack[hash_djb2a(needle->info->pid, needle->info->comm)];
	     ts; ts = ts->next)
		if ((pid == ts->info->pid) && (strcmp(comm, ts->info->comm) == 0))
			return ts;

	return NULL;	/* no success */
}

/*
 *  cpu_stat_sort_freq_add()
 *	add a CPU stat to a sorted list of CPU stats
 */
static void OPTIMIZE3 HOT cpu_stat_sort_freq_add(
	cpu_stat_t **sorted,		/* CPU stat sorted list */
	cpu_stat_t *const new)		/* CPU stat to add */
{
	while (*sorted) {
		if ((*sorted)->delta < new->delta) {
			new->sorted_usage_next = *(sorted);
			break;
		}
		sorted = &(*sorted)->sorted_usage_next;
	}
	*sorted = new;
}

/*
 *  cpu_stat_diff()
 *	find difference in tick count between to hash table samples of CPU
 *	stats.  We are interested in just current and new CPU stats,
 *	not ones that silently die
 */
static void cpu_stat_diff(
	const double duration,			/* time between each sample */
	const uint64_t nr_ticks,		/* ticks per second */
	const int32_t n_lines,			/* number of lines to output */
	const double time_now,			/* time right now */
	cpu_stat_t *const cpu_stats_old[],	/* old CPU stats samples */
	cpu_stat_t *const cpu_stats_new[])	/* new CPU stats samples */
{
	size_t i;
	cpu_stat_t *sorted = NULL;
	const bool do_sample_add = (opt_flags & OPT_SAMPLES);

	for (i = 0; i < TABLE_SIZE; i++) {
		cpu_stat_t *cs;

		for (cs = cpu_stats_new[i]; cs; cs = cs->next) {
			cpu_stat_t *found =
				cpu_stat_find(cpu_stats_old, cs);
			if (found) {
				cs->udelta = cs->utime - found->utime;
				cs->sdelta = cs->stime - found->stime;
				cs->delta  = cs->udelta + cs->sdelta;
				cs->time_delta = cs->time - found->time;
				if (cs->delta >= (int64_t)opt_threshold) {
					cs->old = true;
					if (cs->udelta + cs->sdelta > 0)
						cpu_stat_sort_freq_add(&sorted, cs);
					if (do_sample_add)
						sample_add(cs, time_now);
					found->info->total += cs->delta;
					found->info->utotal += cs->udelta;
					found->info->stotal += cs->sdelta;
					found->info->ticks = cs->utime +
							     cs->stime;
				}
			} else {
				cs->delta = cs->udelta = cs->sdelta = 0;
				cs->time_delta = duration;
				if (cs->delta >= (int64_t)opt_threshold) {
					cs->old = false;
					if (do_sample_add)
						sample_add(cs, time_now);
				}
			}
		}
	}

	if (!(opt_flags & OPT_QUIET)) {
		int32_t j = 0;
		double cpu_u_total = 0.0, cpu_s_total = 0.0;

		info_banner_dump(time_now);
		while (sorted) {
			double cpu_u_usage =
				100.0 * (double)sorted->udelta /
				(double)(nr_ticks);
			double cpu_s_usage =
				100.0 * (double)sorted->sdelta /
				(double)(nr_ticks);
			double cpu_t_usage = cpu_u_usage + cpu_s_usage;

			if ((n_lines == -1) || (j < n_lines)) {
				j++;
				if (cpu_t_usage > 0.0)
					info_dump(sorted->udelta, sorted->sdelta,
						nr_ticks, sorted->info,
						&cpu_u_total, &cpu_s_total);
			}
			sorted = sorted->sorted_usage_next;
		}
		info_total_dump(cpu_u_total, cpu_s_total);
	}
}

/*
 *  get_proc_stat()
 *	read /proc/stat
 */
static int get_proc_stat(proc_stat_t * const proc_stat)
{
	FILE *fp;
	char buffer[4096];

	(void)memset(proc_stat, 0, sizeof(*proc_stat));

	fp = fopen("/proc/stat", "r");
	if (UNLIKELY(!fp))
		return -1;
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		register char *ptr = buffer;
		register uint32_t hash = 0;
		size_t i;

		while (*ptr != ' ') {
			if (*ptr == '\0')
				goto next;
			hash <<= 3;
			hash ^= *ptr;
			ptr++;
		}
		for (i = 0; i < SIZEOF_ARRAY(fields); i++) {
			char *dummy;
			if (hash == fields[i].hash) {
				*((uint64_t *)(((uint8_t *)proc_stat) +
					fields[i].offset)) =
						strtouint64(ptr + 1, &dummy);
				break;
			}
		}
next:		;
	}
	(void)fclose(fp);
	return 0;
}

/*
 *  proc_stat_diff()
 *	compute delta between last proc_stat sample
 */
static inline void proc_stat_diff(
	const proc_stat_t *old,
	const proc_stat_t *new,
	proc_stat_t *const delta)
{
	delta->ctxt = new->ctxt - old->ctxt;
	delta->irq = new->irq - old->irq;
	delta->softirq = new->softirq - old->softirq;
	delta->processes = new->processes - old->processes;
	delta->running = new->running;
	delta->blocked = new->blocked;
}

/*
 *  proc_stat_dump()
 *	dump out proc_stat stats
 */
static inline void proc_stat_dump(
	const proc_stat_t *delta,
	const double duration)
{
	const double scale = 1.0 / duration;
	char buffer[128], *ptr = buffer;

	ptr += putdouble_decpl(ptr, scale * delta->ctxt, 1);
	ptr += putstr(ptr, 9, " Ctxt/s, ");
	ptr += putdouble_decpl(ptr, scale * delta->irq, 1);
	ptr += putstr(ptr, 8, " IRQ/s, ");
	ptr += putdouble_decpl(ptr, scale * delta->softirq, 1);
	ptr += putstr(ptr, 12, " softIRQ/s, ");
	ptr += putdouble_decpl(ptr, scale * delta->processes, 1);
	ptr += putstr(ptr, 14, " new tasks/s, ");
	ptr += putuint(ptr, delta->running);
	ptr += putstr(ptr, 10, " running, ");
	ptr += putuint(ptr, delta->blocked);
	ptr += putstr(ptr, 9, " blocked");
	df.df_putstrnl(buffer, ptr - buffer);
}

/*
 *  get_cpustats()
 *	scan /proc/cpu_stats and populate a cpu stat hash table with
 *	unique tasks
 */
static void get_cpustats(
	cpu_stat_t *cpu_stats[],
	const double time_now)
{
	DIR *dir;
	struct dirent *entry;
	static pid_t my_pid;

	if (UNLIKELY(((opt_flags & OPT_IGNORE_SELF) && (my_pid == 0))))
		my_pid = getpid();

	if (UNLIKELY((dir = opendir("/proc")) == NULL)) {
		(void)fprintf(stderr, "Cannot read directory /proc\n");
		return;
	}
	while ((entry = readdir(dir)) != NULL) {
		cpu_info_t info;
		uint64_t utime;
		uint64_t stime;
		char filename[PATH_MAX], *fnptr;
		char buffer[4096];
		char *ptr = buffer, *endptr, *tmp;
		ssize_t len;
		int fd, skip;

		if (!isdigit(entry->d_name[0]))
			continue;

		fnptr = filename;
		fnptr += putstr(fnptr, 6, "/proc/");
		fnptr += putstr(fnptr, PATH_MAX - 6, entry->d_name);
		(void)putstr(fnptr, 5, "/stat");
		if ((fd = open(filename, O_RDONLY)) < 0)
			continue;

		len = read(fd, buffer, sizeof(buffer) - 1);
		(void)close(fd);
		if (UNLIKELY(len <= 1))
			continue;

		buffer[len] = '\0';

		/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */

		/*
		 *  We used to use scanf but this is really expensive and it
		 *  is far faster to parse the data via a more tedious means
		 *  of scanning down the buffer manually..
		 */
		info.pid = (pid_t)strtouint32(ptr, &endptr);
		if (endptr == ptr)
			continue;
		ptr = endptr;
		if (UNLIKELY(*ptr != ' '))
			continue;
		ptr++;
		if (UNLIKELY((*ptr != '(')))
			continue;
		ptr++;
		tmp = info.comm;
		while ((*ptr != '\0') && (*ptr !=')') &&
		       ((size_t)(tmp - info.comm) < sizeof(info.comm)))
			*tmp++ = *ptr++;
		if (UNLIKELY(*ptr != ')'))
			continue;
		*tmp = '\0';
		ptr++;
		if (UNLIKELY(*ptr != ' '))
			continue;
		ptr++;
		info.state = *ptr;
		ptr++;

		/* Skip over fields to the 14th field (utime) */
		skip = 11;
		while (skip > 0 && *ptr) {
			if (*ptr == ' ')
				skip--;
			ptr++;
		}
		if (UNLIKELY(*ptr == '\0'))
			continue;
		/* Field 14, utime */
		utime = strtouint64(ptr, &endptr);
		if (UNLIKELY(endptr == ptr))
			continue;
		ptr = endptr;
		if (UNLIKELY(*ptr != ' '))
			continue;
		ptr++;
		/* Field 15, stime */
		stime = strtouint64(ptr, &endptr);
		if (UNLIKELY(endptr == ptr))
			continue;
		ptr = endptr;
		skip = 24;
		while (skip > 0 && *ptr) {
			if (*ptr == ' ')
				skip--;
			ptr++;
		}
		if (UNLIKELY((*ptr == '\0')))
			continue;
		/* Field 39, processor */
		info.processor = (int)strtouint32(ptr, &endptr);
		if (UNLIKELY(endptr == ptr))
			continue;
		if (UNLIKELY(((opt_flags & OPT_IGNORE_SELF) &&
			     (my_pid == info.pid))))
			continue;
		if (UNLIKELY(((opt_flags & OPT_MATCH_PID) &&
			     (opt_pid != info.pid))))
			continue;

		info.total = 0;
		info.ticks = 0;
		cpu_stat_add(cpu_stats, &info, time_now, utime, stime);
	}

	(void)closedir(dir);
}

/*
 *  cpu_freq_average()
 *	get average CPU frequency
 */
static double cpu_freq_average(const uint32_t max_cpus)
{
	size_t i, n = 0;
	double total_freq = 0;

	for (i = 0; i < max_cpus; i++) {
		char filename[PATH_MAX], *fnptr;
		int fd;

		fnptr = filename;
		fnptr += putstr(fnptr, 28, "/sys/devices/system/cpu/cpu");
		fnptr += putuint(fnptr, i);
		(void)putstr(fnptr, 25, "/cpufreq/scaling_cur_freq");

		if (LIKELY((fd = open(filename, O_RDONLY)) > -1)) {
			char buffer[64];
			ssize_t ret;

			ret = read(fd, buffer, sizeof(buffer) - 1);
			(void)close(fd);
			if (LIKELY(ret > 0)) {
				double freq;
				char *dummy;

				buffer[ret] = '\0';
				freq = 1000.0 * (double)strtouint64(buffer, &dummy);
				total_freq += freq;
				n++;
			}
		}
	}
	return n > 0 ? total_freq / n : 0.0;
}

/*
 *  cpu_freq_format()
 *	scale cpu freq into a human readable form
 */
static char *cpu_freq_format(const double freq)
{
	static char buffer[40];
	char *suffix = "EHz", *ptr = buffer;
	double scale = 1e18;
	size_t i;

	for (i = 0; i < SIZEOF_ARRAY(cpu_freq_scale); i++) {
		if (freq < cpu_freq_scale[i].threshold) {
			suffix = cpu_freq_scale[i].suffix;
			scale = cpu_freq_scale[i].scale;
			break;
		}
	}

	ptr += putdouble_decpl(buffer, freq / scale, 2);
	*(ptr++) = ' ';
	putstr(ptr, 3, suffix);

	return buffer;
}

/*
 *  cpus_online()
 *	determine number of CPUs online
 */
static char *cpus_online(void)
{
	int fd;
	static char buffer[4096];
	uint32_t cpus = 0;
	char *ptr = buffer;
	ssize_t ret;

	if (UNLIKELY((fd = open("/sys/devices/system/cpu/online", O_RDONLY)) < 0))
		goto unknown;
	ret = read(fd, buffer, sizeof(buffer) - 1);
	(void)close(fd);
	if (UNLIKELY(ret < 0))
		goto unknown;

	for (;;) {
		char ch;
		int32_t n1;

		n1 = strtouint32(ptr, &ptr);
		ch = *ptr;
		if (ch == '-') {
			int32_t n2, range;
			ptr++;

			n2 = strtouint32(ptr, &ptr);
			range = 1 + n2 - n1;
			if (range > 0)
				cpus += range;
			n1 = -1;
			ch = *ptr;
			/* next char must be EOS or , */
		}
		if (ch == '\0' || ch == '\n') {
			if (n1 > -1)
				cpus++;
			break;
		} else if (ch == ',') {
			ptr++;
			if (n1 > -1)
				cpus++;
			continue;
		} else
			goto unknown;
	}
	(void)snprintf(buffer, sizeof(buffer), "%" PRId32, cpus);

	return buffer;
unknown:
	return "unknown";
}

/*
 *  load_average()
 *	get current load average stats
 */
static char *load_average(void)
{
	static char buffer[4096];
	char *ptr = buffer;
	ssize_t len;
	int fd, skip = 3;

	if (UNLIKELY((fd = open("/proc/loadavg", O_RDONLY)) < 0))
		goto unknown;
	len = read(fd, buffer, sizeof(buffer) - 1);
	(void)close(fd);
	if (UNLIKELY(len < 1))
		goto unknown;
	buffer[len] = '\0';

	for (;;) {
		if (*ptr == '\0') {
			skip--;
			break;
		}
		if (*ptr == ' ') {
			skip--;
			if (skip == 0) {
				*ptr = '\0';
				break;
			}
		}
		ptr++;
	}
	if (skip != 0)
		goto unknown;

	return buffer;
unknown:
	return "unknown";

}

/*
 *  load_online_dump()
 *	dump load and cpu related stats
 */
static inline void load_online_dump(const uint32_t max_cpus)
{
	double avg_cpu_freq = cpu_freq_average(max_cpus);
	char buffer[128], *ptr = buffer;

	ptr += putstr(ptr, 10, "Load Avg ");
	ptr += putstr(ptr, 20, load_average());
	if (avg_cpu_freq > 0.0) {
		ptr += putstr(ptr, 12, ", Freq Avg ");
		ptr += putstr(ptr, 20, cpu_freq_format(avg_cpu_freq));
	}
	ptr += putstr(ptr, 2, ", ");
	ptr += putstr(ptr, 10, cpus_online());
	ptr += putstr(ptr, 12, " CPUs online");

	df.df_putstrnl(buffer, ptr - buffer);
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	(void)printf(APP_NAME ", version " VERSION "\n\n"
		"Usage: " APP_NAME " [options] [duration] [count]\n"
		" -h help\n"
		" -a calculate CPU utilisation based on all the CPU ticks\n"
		"    rather than per CPU tick\n"
		" -c get command name from processes comm field\n"
		" -d strip directory basename off command information\n"
		" -D show distribution of CPU utilisation stats at end\n"
		" -g show grand total of CPU utilisation stats at end\n"
		" -i ignore " APP_NAME " in the statistics\n"
		" -l show long (full) command information\n"
		" -n specifies number of tasks to display\n"
		" -p just show utilisation for a specified PID\n"
		" -q run quietly, useful with option -r\n"
		" -r specifies a comma separated values output file to dump\n"
		"    samples into\n"
		" -s show short command information\n"
		" -S timestamp output\n"
		" -t specifies a task tick count threshold where samples less\n"
                "    than this are ignored\n"
		" -T show total CPU utilisation statistics\n"
		" -x show extra stats (load average, avg cpu freq, etc)\n"
		" -X top-like curses based display mode\n");
}

int main(int argc, char **argv)
{
	cpu_stat_t **cpu_stats_old, **cpu_stats_new, **cpu_stats_tmp;
	struct sigaction new_action;
	proc_stat_t proc_stats[2];
	proc_stat_t *proc_stat_old, *proc_stat_new,
		    *proc_stat_tmp, proc_stat_delta;
	uint32_t max_cpus = sysconf(_SC_NPROCESSORS_CONF);
	double duration_secs = 1.0, time_start, time_now;
	int64_t count = 1, t = 1;
	uint64_t nr_ticks, total_ticks = 0;
	int32_t n_lines = -1;
	uint32_t samples = 0;
	bool forever = true;
	bool redo = false;
	int i;

	clock_ticks = (uint64_t)sysconf(_SC_CLK_TCK);

	for (;;) {
		int c = getopt(argc, argv, "acdDghiln:qr:sSt:Tp:xX");
		if (c == -1)
			break;
		switch (c) {
		case 'a':
			opt_flags |= OPT_TICKS_ALL;
			break;
		case 'c':
			opt_flags |= OPT_CMD_COMM;
			break;
		case 'd':
			opt_flags |= OPT_DIRNAME_STRIP;
			break;
		case 'D':
			opt_flags |= (OPT_SAMPLES | OPT_DISTRIBUTION);
			break;
		case 'g':
			opt_flags |= OPT_GRAND_TOTAL;
			break;
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		case 'i':
			opt_flags |= OPT_IGNORE_SELF;
			break;
		case 'l':
			opt_flags |= OPT_CMD_LONG;
			break;
		case 'n':
			errno = 0;
			n_lines = (int32_t)strtol(optarg, NULL, 10);
			if (errno) {
				(void)fprintf(stderr, "Invalid value for -n option\n");
				exit(EXIT_FAILURE);
			}
			if (n_lines < 1) {
				(void)fprintf(stderr,
					"-n option must be greater than 0\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'p':
			errno = 0;
			opt_pid = strtol(optarg, NULL, 10);
			if (errno) {
				(void)fprintf(stderr,
					"Invalid value for -o option\n");
				exit(EXIT_FAILURE);
			}
			opt_flags |= OPT_MATCH_PID;
			break;
		case 's':
			opt_flags |= OPT_CMD_SHORT;
			break;
		case 'S':
			opt_flags |= OPT_TIMESTAMP;
			break;
		case 't':
			opt_threshold = atof(optarg);
			if (opt_threshold < 0.0) {
				(void)fprintf(stderr,
					"-t threshold must be 0 or more.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'T':
			opt_flags |= OPT_TOTAL;
			break;
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 'r':
			csv_results = optarg;
			opt_flags |= OPT_SAMPLES;
			break;
		case 'x':
			opt_flags |= OPT_EXTRA_STATS;
			break;
		case 'X':
			opt_flags |= OPT_TOP;
			break;
		default:
			show_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (count_bits(opt_flags & OPT_CMD_ALL) > 1) {
		(void)fprintf(stderr, "Cannot have -c, -l, -s at same time.\n");
		exit(EXIT_FAILURE);
	}
	if (optind < argc) {
		duration_secs = atof(argv[optind++]);
		if (duration_secs < 0.333) {
			(void)fprintf(stderr, "Duration must 0.333 or more\n");
			exit(EXIT_FAILURE);
		}
	}
	if (optind < argc) {
		forever = false;
		errno = 0;
		count = (int64_t)strtoll(argv[optind++], NULL, 10);
		if (errno) {
			(void)fprintf(stderr, "Invalid value for count\n");
			exit(EXIT_FAILURE);
		}
		if (count < 1) {
			(void)fprintf(stderr, "Count must be greater than 0\n");
			exit(EXIT_FAILURE);
		}
	}
	opt_threshold *= duration_secs;

	pid_max_digits = get_pid_max_digits();

	(void)memset(&new_action, 0, sizeof(new_action));
	for (i = 0; signals[i] != -1; i++) {
		new_action.sa_handler = handle_sig;
		(void)sigemptyset(&new_action.sa_mask);
		new_action.sa_flags = 0;

		if (sigaction(signals[i], &new_action, NULL) < 0) {
			(void)fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	(void)memset(&new_action, 0, sizeof(new_action));
	new_action.sa_handler = handle_sigwinch;
	if (sigaction(SIGWINCH, &new_action , NULL) < 0) {
		(void)fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
			errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	cpu_stats_old = calloc(TABLE_SIZE, sizeof(*cpu_stats_old));
	cpu_stats_new = calloc(TABLE_SIZE, sizeof(*cpu_stats_new));

	if (UNLIKELY(cpu_stats_old == NULL || cpu_stats_new == NULL)) {
		(void)fprintf(stderr, "Cannot allocate CPU statistics tables\n");
		exit(EXIT_FAILURE);
	}
	proc_stat_old = &proc_stats[0];
	proc_stat_new = &proc_stats[1];
	time_now = time_start = gettime_to_double();
	get_cpustats(cpu_stats_old, time_now);
	if (opt_flags & OPT_EXTRA_STATS)
		get_proc_stat(proc_stat_old);
	nr_ticks = get_ticks();

	/* Set display functions */
	df = (opt_flags & OPT_TOP) ? df_top : df_normal;
	df.df_setup();
	df.df_winsize(true);

	while (!stop_cpustat && (forever || count--)) {
		struct timeval tv;
		double secs, duration, right_now;

		df.df_clear();
		cury = 0;

		/* Timeout to wait for in the future for this sample */
		secs = time_start + ((double)t * duration_secs) - time_now;
		/* Play catch-up, probably been asleep */
		if (secs < 0.0) {
			t = ceil((time_now - time_start) / duration_secs);
			secs = time_start +
				((double)t * duration_secs) - time_now;
			/* We don't get sane stats if duration is too small */
			if (secs < 0.5)
				secs += duration_secs;
		} else {
			if (!redo)
				t++;
		}
		redo = false;

		double_to_timeval(secs, &tv);
retry:
		if (UNLIKELY(select(0, NULL, NULL, NULL, &tv) < 0)) {
			if (errno == EINTR) {
				if (!resized) {
					stop_cpustat = true;
					df.df_winsize(true);
				} else {
					redo = true;
					if (timeval_to_double(&tv) > 0.0)
						goto retry;
				}
			} else {
				(void)fprintf(stderr,
					"select failed: errno=%d (%s)\n",
					errno, strerror(errno));
				break;
			}
		}
		/*
		 *  total ticks can change depending on number of CPUs online
		 *  so we need to account for these changing.
		 */
		right_now = gettime_to_double();
		duration = duration_round(right_now - time_now);
		nr_ticks = get_ticks() * duration;
		total_ticks += nr_ticks;
		time_now = right_now;
		get_cpustats(cpu_stats_new, time_now);

		df.df_winsize(redo);
		df.df_refresh();

		if (opt_flags & OPT_EXTRA_STATS) {
			get_proc_stat(proc_stat_new);
			proc_stat_diff(proc_stat_old, proc_stat_new,
					&proc_stat_delta);
			load_online_dump(max_cpus);
			proc_stat_dump(&proc_stat_delta, duration);
		}

		cpu_stat_diff(duration, nr_ticks, n_lines, time_now,
			cpu_stats_old, cpu_stats_new);
		cpu_stat_free_contents(cpu_stats_old);

		cpu_stats_tmp = cpu_stats_old;
		cpu_stats_old = cpu_stats_new;
		cpu_stats_new = cpu_stats_tmp;

		proc_stat_tmp = proc_stat_old;
		proc_stat_old = proc_stat_new;
		proc_stat_new = proc_stat_tmp;
		samples++;

		df.df_refresh();
		df.df_linebreak();
	}

	df.df_endwin();
	df = df_normal;

	time_now = gettime_to_double();
	samples_dump(csv_results, time_now - time_start, time_now,
		nr_ticks, total_ticks, samples);
	if (opt_flags & OPT_DISTRIBUTION) {
		samples_distribution(nr_ticks);
		cpu_distribution(total_ticks);
	}
	cpu_stat_free_contents(cpu_stats_old);
	cpu_stat_free_contents(cpu_stats_new);
	free(cpu_stats_old);
	free(cpu_stats_new);
	samples_free();
	cpu_info_list_free();
	cpu_stat_list_free();
	pid_info_hash_free();

	exit(EXIT_SUCCESS);
}
