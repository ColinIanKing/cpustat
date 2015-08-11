/*
 * Copyright (C) 2011-2015 Canonical
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
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <float.h>
#include <fcntl.h>

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

#define	PROC_STAT_SCN_IRQ	(0x01)
#define PROC_STAT_SCN_SOFTIRQ	(0x02)
#define PROC_STAT_SCN_CTXT	(0x04)
#define PROC_STAT_SCN_PROCS_RUN	(0x08)
#define PROC_STAT_SCN_PROCS_BLK	(0x10)
#define PROC_STAT_SCN_PROCS	(0x20)
#define PROC_STAT_SCN_ALL	(0x3f)

/* Histogram specific constants */
#define MAX_DIVISIONS		(20)
#define DISTRIBUTION_WIDTH	(40)

#define _VER_(major, minor, patchlevel) \
	((major * 10000) + (minor * 100) + patchlevel)

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

/* per process cpu information */
typedef struct cpu_info_t {
	struct cpu_info_t *hash_next;	/* Next cpu info in hash */
	struct cpu_info_t *list_next;	/* Next cpu info in list */
	uint64_t	utotal;		/* Usr Space total CPU ticks */
	uint64_t	stotal;		/* Sys Space total CPU ticks */
	uint64_t	total;		/* Total number of CPU ticks */
	uint64_t	ticks;		/* Total life time in CPU ticks */
	char 		*comm;		/* Name of process/kernel task */
	char		*cmdline;	/* Full name of process cmdline */
	char		*ident;		/* Pid + comm identifier */
	pid_t		pid;		/* Process ID */
	bool		kernel_thread;	/* true if a kernel thread */
	int		processor;	/* Last CPU run on */
	char		state;		/* Run state */
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
	pid_t	pid;			/* process ID */
	char	*cmdline;		/* process command line */
} pid_info_t;

typedef struct {
	double		threshold;	/* scaling threashold */
	double		scale;		/* scaling value */
	char 		*suffix;	/* Human Hz scale factor */
} cpu_freq_scale_t;

static cpu_freq_scale_t cpu_freq_scale[] = {
	{ 1e1,  1e0,  "Hz" },
	{ 1e4,  1e3,  "KHz" },
	{ 1e7,  1e6,  "MHz" },
	{ 1e10, 1e9,  "GHz" },
	{ 1e13, 1e12, "THz" },
	{ 1e16, 1e15, "PHz" },
	{ -1.0, -1.0,  NULL }
};

/* scaling factor */
typedef struct {
	const char ch;			/* Scaling suffix */
	const uint64_t scale;		/* Amount to scale by */
} scale_t;

static const scale_t second_scales[] = {
	{ 's',	1 },
	{ 'm',	60 },
	{ 'h',  3600 },
	{ 'd',  24 * 3600 },
	{ 'w',  7 * 24 * 3600 },
	{ 'y',  365 * 24 * 3600 },
	{ ' ',  INT64_MAX },
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
 *  get_ticks()
 *	get ticks
 */
static inline uint64_t get_ticks(void)
{
	return (opt_flags & OPT_TICKS_ALL) ?
		clock_ticks * (uint64_t)sysconf(_SC_NPROCESSORS_ONLN) :
		clock_ticks;
}

/*
 *  secs_to_str()
 *	report seconds in different units.
 */
static const char *secs_to_str(const double secs)
{
	static char buf[16];
	int i;

	for (i = 0; i < 5; i++) {
		if (secs <= second_scales[i + 1].scale)
			break;
	}
	snprintf(buf, sizeof(buf), "%5.2f%c",
		secs / second_scales[i].scale, second_scales[i].ch);
	return buf;
}


/*
 *  get_tm()
 *	fetch tm, will set fields to zero if can't get
 */
static void get_tm(const double time_now, struct tm *tm)
{
	time_t now = (time_t)time_now;

	if (now == ((time_t) -1)) {
		memset(tm, 0, sizeof(struct tm));
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
	struct timeval *tv)
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

        if (gettimeofday(&tv, NULL) < 0) {
                fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
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
 *	count bits set, from C Programming Language 2nd Ed
 */
static unsigned int count_bits(const unsigned int val)
{
	register unsigned int c, n = val;

	for (c = 0; n; c++)
		n &= n - 1;

	return c;
}

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *get_pid_cmdline(const pid_t pid)
{
	static char buffer[4096];
	char *ptr = NULL;
	int fd;
	ssize_t ret;
	pid_info_t *info;
	int h = pid % PID_HASH_SIZE;
	char path[PATH_MAX];
	struct stat statbuf;
	bool statok = false;

	snprintf(path, sizeof(path), "/proc/%u", pid);
	if (stat(path, &statbuf) >= 0) {
		statok = true;
		for (info = pid_info_hash[h]; info; info = info->next) {
			if (info->pid == pid) {
				if (statbuf.st_ctim.tv_sec > info->st_ctim.tv_sec)
					break;
				return info->cmdline;
			}
		}
	}
	snprintf(path, sizeof(path), "/proc/%i/cmdline", pid);
	if ((fd = open(path, O_RDONLY)) < 0)
		goto no_cmd;
	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		(void)close(fd);
		goto no_cmd;
	}
	(void)close(fd);

	if (ret >= (ssize_t)sizeof(buffer))
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
		/* We may be re-using a stale old PID, or we may need a new info */
		if (!info)
			info = calloc(1, sizeof(pid_info_t));
		if (info) {
			info->pid = pid;
			info->cmdline = ptr;
			info->next = pid_info_hash[h];
			info->st_ctim = statbuf.st_ctim;
			pid_info_hash[h] = info;
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

	if (!(opt_flags & OPT_SAMPLES))
		return;

	for (sdl = sample_delta_list_tail; sdl; sdl = sdl->prev) {
		if (sdl->whence == whence) {
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
		if ((sdl = calloc(1, sizeof(sample_delta_list_t))) == NULL) {
			fprintf(stderr, "Cannot allocate sample delta list\n");
			exit(EXIT_FAILURE);
		}
		sdl->whence = whence;
		if (sample_delta_list_head)
			sample_delta_list_tail->next = sdl;
		else
			sample_delta_list_head = sdl;

		sdl->prev = sample_delta_list_tail;
		sample_delta_list_tail = sdl;
	}

	/* Now append the sdi onto the list */
	if ((sdi = calloc(1, sizeof(sample_delta_item_t))) == NULL) {
		fprintf(stderr, "Cannot allocate sample delta item\n");
		exit(EXIT_FAILURE);
	}
	sdi->delta = cpu_stat->delta;
	sdi->time_delta = cpu_stat->time_delta;
	sdi->info = cpu_stat->info;
	sdi->next = sdl->sample_delta_item_list;
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
	cpu_info_t **info1 = (cpu_info_t **)item1;
	cpu_info_t **info2 = (cpu_info_t **)item2;

	if ((*info2)->total == (*info1)->total)
		return 0;

	return ((*info2)->total > (*info1)->total) ? 1 : -1;
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
 *  info_banner_dump()
 *	dump banner for per_info stats
 */
static void info_banner_dump(const double time_now)
{
	char ts[32];

	if (opt_flags & OPT_TIMESTAMP) {
		struct tm tm;

		get_tm(time_now, &tm);
		snprintf(ts, sizeof(ts), "  (%2.2d:%2.2d:%2.2d)",
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	} else {
		*ts = '\0';
	}
	printf("  %%CPU   %%USR   %%SYS   PID S  CPU   Time Task%s\n", ts);
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
	double *u_total,
	double *s_total)
{
	const double cpu_u_usage = 100.0 * (double)uticks / total_ticks;
	const double cpu_s_usage = 100.0 * (double)sticks / total_ticks;
	double cpu_time = ((double)(info->ticks)) / (double)clock_ticks;

	*u_total += cpu_u_usage;
	*s_total += cpu_s_usage;

	printf("%6.2f %6.2f %6.2f %5d %c %4d %s %s%s%s\n",
		cpu_u_usage + cpu_s_usage,
		cpu_u_usage, cpu_s_usage,
		info->pid,
		info->state,
		info->processor,
		secs_to_str(cpu_time),
		info->kernel_thread ?
			"[" : "",
		info->cmdline,
		info->kernel_thread ?
			"]" : "");
}

/*
 *  info_total_dump()
 *	dump out totals of total, system and user times
 */
static void info_total_dump(
	const double u_total,
	const double s_total)
{
	if (opt_flags & OPT_TOTAL)
		printf("%6.2f %6.2f %6.2f Total\n",
			u_total + s_total, u_total, s_total);
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

	if ((sorted_cpu_infos =
	     calloc(cpu_info_list_length, sizeof(cpu_info_t*))) == NULL) {
		fprintf(stderr,
			"Cannot allocate buffer for sorting cpu_infos\n");
		exit(EXIT_FAILURE);
	}

	/* Just want the CPUs with some non-zero total */
	for (n = 0, cpu_info = cpu_info_list; cpu_info;
	     cpu_info = cpu_info->list_next) {
		if (cpu_info->total > 0)
			sorted_cpu_infos[n++] = cpu_info;
	}

	qsort(sorted_cpu_infos, n, sizeof(cpu_info_t *), info_compare_total);

	if (opt_flags & OPT_GRAND_TOTAL) {
		double cpu_u_total = 0.0, cpu_s_total = 0.0;

		printf("Grand Total (from %" PRIu32 " samples, %.1f seconds):\n",
			samples, duration);
		info_banner_dump(time_now);
		for (i = 0; i < n; i++) {
			info_dump(sorted_cpu_infos[i]->utotal, sorted_cpu_infos[i]->stotal,
				total_ticks, sorted_cpu_infos[i],
				&cpu_u_total, &cpu_s_total);
		}
		info_total_dump(cpu_u_total, cpu_s_total);
		putchar('\n');
	}

	if (!filename) {
		free(sorted_cpu_infos);
		return;
	}

	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot write to file %s\n", filename);
		free(sorted_cpu_infos);
		return;
	}
	fprintf(fp, "Task:%s", (opt_flags & OPT_TIMESTAMP) ? "," : "");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%s (%d)", sorted_cpu_infos[i]->comm,
			sorted_cpu_infos[i]->pid);
	fprintf(fp, "\n");

	fprintf(fp, "Ticks:%s", (opt_flags & OPT_TIMESTAMP) ? "," : "");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%" PRIu64, sorted_cpu_infos[i]->total);
	fprintf(fp, "\n");

	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		if (first_time < 0)
			first_time = sdl->whence;

		fprintf(fp, "%f", duration_round(sdl->whence - first_time));
		if (opt_flags & OPT_TIMESTAMP) {
			struct tm tm;

			get_tm(sdl->whence, &tm);
			fprintf(fp, ",%2.2d:%2.2d:%2.2d",
				tm.tm_hour, tm.tm_min, tm.tm_sec);
		}

		/* Scan in CPU info order to be consistent for all sdl rows */
		for (i = 0; i < n; i++) {
			sample_delta_item_t *sdi =
				sample_find(sdl, sorted_cpu_infos[i]);
			if (sdi) {
				double duration =
					duration_round(sdi->time_delta);
				fprintf(fp,",%f",
					(duration == 0.0) ? 0.0 :
					100.0 * (double)sdi->delta /
					(duration * (double)nr_ticks));
			} else
				fprintf(fp,", ");
		}
		fprintf(fp, "\n");
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
	const double duration,
	uint64_t nr_ticks)
{
	cpu_info_t *cpu_info;
	double total_ticks = duration * (double)nr_ticks;
	int i, cpu_max = max_processors();
	uint64_t utotal[cpu_max], stotal[cpu_max];

	memset(utotal, 0, sizeof(utotal));
	memset(stotal, 0, sizeof(stotal));

	for (cpu_info = cpu_info_list; cpu_info;
	     cpu_info = cpu_info->list_next) {
		int cpu = cpu_info->processor;
		utotal[cpu] += cpu_info->utotal;
		stotal[cpu] += cpu_info->stotal;
	}
	printf("Distribution of CPU utilisation (per CPU):\n");
	printf(" CPU#   USR%%   SYS%%\n");
	for (i = 0; i < cpu_max; i++)
		printf("%5d %6.2f %6.2f\n",
			i,
			100.0 * (double)utotal[i] / total_ticks,
			100.0 * (double)stotal[i] / total_ticks);
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
	double scale = 100.0 / (double)nr_ticks;

	memset(bucket, 0, sizeof(bucket));

	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		sample_delta_item_t *sdi = sdl->sample_delta_item_list;

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
		printf("Too few samples, cannot compute distribution\n");
		return;
	}

	if (max - min == 0.0) {
		printf("Range is zero, cannot compute distribution\n");
		return;
	}
	division = ((max * 1.000001) - min) / (MAX_DIVISIONS);
	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		sample_delta_item_t *sdi = sdl->sample_delta_item_list;

		for (sdi = sdl->sample_delta_item_list; sdi; sdi = sdi->next) {
			double val = 100.0 * (double)sdi->delta / (double)nr_ticks;
			int v = floor(val - min) / division;
			v = v > MAX_DIVISIONS - 1 ? MAX_DIVISIONS -1 : v;
			bucket[v]++;
			total++;
			if (max_bucket < bucket[v])
				max_bucket = bucket[v];
		}
	}
	printf("Distribution of CPU utilisation (per Task):\n");
	printf("%% CPU Utilisation   Count   (%%)\n");
	for (prev = min, i = 0; i < MAX_DIVISIONS; i++, prev += division) {
		printf("%6.2f - %6.2f  %8u %6.2f\n",
			prev, prev + division - 0.001,
			bucket[i],
			100.0 * (double)bucket[i] / (double)total);
	}
	putchar('\n');
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

	for (info = cpu_info_hash[hash]; info; info = info->hash_next) {
		if (strcmp(new_info->ident, info->ident) == 0)
			return info;
	}

	if ((info = calloc(1, sizeof(cpu_info_t))) == NULL) {
		fprintf(stderr, "Cannot allocate CPU info\n");
		exit(EXIT_FAILURE);
	}

	info->pid = new_info->pid;
	if ((info->comm = strdup(new_info->comm)) == NULL) {
		fprintf(stderr, "Cannot allocate CPU comm field info\n");
		exit(EXIT_FAILURE);
	}
	info->kernel_thread = new_info->kernel_thread;

	if ((new_info->cmdline == NULL) || (opt_flags & OPT_CMD_COMM)) {
		info->cmdline = info->comm;
	} else {
		if ((info->cmdline = strdup(new_info->cmdline)) == NULL) {
			fprintf(stderr, "Cannot allocate CPU cmdline field info\n");
			exit(EXIT_FAILURE);
		}
	}

	info->ident = strdup(new_info->ident);
	info->state = new_info->state;
	info->processor = new_info->processor;

	if (info->comm == NULL ||
	    info->cmdline == NULL ||
	    info->ident == NULL) {
		fprintf(stderr, "Out of memory allocating a cpu stat fields\n");
		exit(1);
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
	free(info->comm);
	free(info->ident);
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
static uint32_t OPTIMIZE3 HOT hash_djb2a(const char *str)
{
	register uint32_t hash = 5381;
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
	int i;

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
	const double time_now,		/* time sample was taken */
	const pid_t pid,		/* PID of task */
	const char *comm,		/* Name of task */
	const char state,		/* State field */
	const uint64_t utime,		/* user time in ticks */
	const uint64_t stime,		/* system time in ticks */
	const int processor)		/* processor it ran on */
{
	char ident[1024];
	cpu_stat_t *cs, *cs_new;
	cpu_info_t info;
	uint32_t h;

	snprintf(ident, sizeof(ident), "%x%s", pid, comm);

	h = hash_djb2a(ident);
	cs = cpu_stats[h];

	for (cs = cpu_stats[h]; cs; cs = cs->next) {
		if (strcmp(cs->info->ident, ident) == 0) {
			cs->utime += utime;
			cs->stime += stime;
			cs->info->state = state;
			cs->info->processor = processor;
			return;
		}
	}
	/* Not found, it is new! */

	if (cpu_stat_free_list) {
		/* Re-use one from the free list */
		cs_new = cpu_stat_free_list;
		cpu_stat_free_list = cs_new->next;
		memset(cs_new, 0, sizeof(*cs_new));
	} else {
		if ((cs_new = calloc(1, sizeof(cpu_stat_t))) == NULL) {
			fprintf(stderr,
				"Out of memory allocating a cpu stat\n");
			exit(1);
		}
	}

	info.pid = pid;
	info.comm = (char *)comm;
	info.cmdline = get_pid_cmdline(pid);
	info.kernel_thread = (info.cmdline == NULL);
	info.ident = ident;
	info.processor = processor;
	info.state = state;

	cs_new->utime = utime;
	cs_new->stime = stime;
	cs_new->info = cpu_info_find(&info, h);
	cs_new->time = time_now;
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
	char ident[1024];

	snprintf(ident, sizeof(ident), "%x%s",
		needle->info->pid, needle->info->comm);

	for (ts = haystack[hash_djb2a(ident)]; ts; ts = ts->next)
		if (strcmp(ts->info->ident, ident) == 0)
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
	int i;
	cpu_stat_t *sorted = NULL;

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
					sample_add(cs, time_now);
					found->info->total += cs->delta;
					found->info->utotal += cs->udelta;
					found->info->stotal += cs->sdelta;
					found->info->ticks = cs->utime + cs->stime;
				}
			} else {
				cs->delta = cs->udelta = cs->sdelta = 0;
				cs->time_delta = duration;
				if (cs->delta >= (int64_t)opt_threshold) {
					cs->old = false;
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
				(duration * (double)(nr_ticks));
			double cpu_s_usage =
				100.0 * (double)sorted->sdelta /
				(duration * (double)(nr_ticks));
			double cpu_t_usage = cpu_u_usage + cpu_s_usage;

			if ((n_lines == -1) || (j < n_lines)) {
				j++;
				if (cpu_t_usage > 0.0)
					info_dump(sorted->udelta, sorted->sdelta,
						nr_ticks * duration, sorted->info,
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
static int get_proc_stat(proc_stat_t *proc_stat)
{
	FILE *fp;
	char buffer[4096];
	unsigned int got_flags = 0;

	memset(proc_stat, 0, sizeof(proc_stat_t));

	fp = fopen("/proc/stat", "r");
	if (!fp) {
		return -1;
	}
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!strncmp(buffer, "intr ", 5)) {
			proc_stat->irq = (uint64_t)atoll(buffer + 5);
			got_flags |= PROC_STAT_SCN_IRQ;
		} else if (!strncmp(buffer, "softirq ", 8)) {
			proc_stat->softirq = (uint64_t)atoll(buffer + 8);
			got_flags |= PROC_STAT_SCN_SOFTIRQ;
		} else if (!strncmp(buffer, "ctxt ", 5)) {
			proc_stat->ctxt = (uint64_t)atoll(buffer + 5);
			got_flags |= PROC_STAT_SCN_CTXT;
		} else if (!strncmp(buffer, "procs_running ", 14)) {
			proc_stat->running = (uint64_t)atoll(buffer + 14);
			got_flags |= PROC_STAT_SCN_PROCS_RUN;
		} else if (!strncmp(buffer, "procs_blocked ", 14)) {
			proc_stat->blocked = (uint64_t)atoll(buffer + 14);
			got_flags |= PROC_STAT_SCN_PROCS_BLK;
		} else if (!strncmp(buffer, "processes ", 10)) {
			proc_stat->processes = (uint64_t)atoll(buffer + 10);
			got_flags |= PROC_STAT_SCN_PROCS;
		}
		if ((got_flags & PROC_STAT_SCN_ALL) == PROC_STAT_SCN_ALL)
			break;
	}
	fclose(fp);
	return 0;
}

/*
 *  proc_stat_diff()
 *	compute delta between last proc_stat sample
 */
static inline void proc_stat_diff(
	const proc_stat_t *old,
	const proc_stat_t *new,
	proc_stat_t *delta)
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
static inline void proc_stat_dump(const proc_stat_t *delta)
{
	printf("%" PRIu64 " Ctxt/s, %" PRIu64 " IRQ/s, %" PRIu64 " softIRQ/s, "
		"%" PRIu64 " new tasks/s, %" PRIu64 " running, %" PRIu64 " blocked\n",
		delta->ctxt,
		delta->irq,
		delta->softirq,
		delta->processes,
		delta->running,
		delta->blocked);
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

	if ((opt_flags & OPT_IGNORE_SELF) && (my_pid == 0))
		my_pid = getpid();

	if ((dir = opendir("/proc")) == NULL) {
		fprintf(stderr, "Cannot read directory /proc\n");
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		char filename[PATH_MAX];
		FILE *fp;
		char comm[20];
		char state;
		pid_t pid;
		uint64_t utime;
		uint64_t stime;
		int n, processor;

		if (!isdigit(entry->d_name[0]))
			continue;

		snprintf(filename, sizeof(filename), "/proc/%s/stat",
			entry->d_name);
		if ((fp = fopen(filename, "r")) == NULL)
			continue;

		/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */
		n = fscanf(fp, "%8d (%20[^)]) %c %*d %*d %*d %*d %*d "
				"%*u %*u %*u %*u %*u %20" SCNu64 "%20" SCNu64
				"%*d %*d %*d %*d %*d %*d "
				"%*u %*u %*d %*u %*u %*u "
				"%*u %*u %*u %*u %*u "
				"%*u %*u %*u %*u %*u "
				"%*d %d",
			&pid, comm, &state, &utime, &stime, &processor);
		(void)fclose(fp);

		if ((opt_flags & OPT_IGNORE_SELF) && (my_pid == pid))
			continue;
		if ((opt_flags & OPT_MATCH_PID) && (opt_pid != pid))
			continue;

		if (n == 6)
			cpu_stat_add(cpu_stats, time_now, pid, comm,
				state, utime, stime, processor);
	}

	(void)closedir(dir);
}

/*
 *  cpu_freq_average()
 *	get averagr CPU frequency
 */
static double cpu_freq_average(uint32_t max_cpus)
{
	uint32_t i, n = 0;
	double total_freq = 0;

	for (i = 0; i < max_cpus; i++) {
		char path[PATH_MAX];
		int fd;

		snprintf(path, sizeof(path),
			"/sys/devices/system/cpu/cpu%" PRIu32 "/cpufreq/scaling_cur_freq", i);
		if ((fd = open(path, O_RDONLY)) > -1) {
			char buffer[64];

			if (read(fd, buffer, sizeof(buffer)) > 0) {
				uint64_t freq = (uint64_t)atoll(buffer);
				total_freq += (double)freq * 1000.0;
				n++;
			}
			(void)close(fd);
		}
	}
	return n > 0 ? total_freq / (double)n : 0.0;
}

/*
 *  cpu_freq_format()
 *	scale cpu freq into a human readable form
 */
static const char *cpu_freq_format(double freq)
{
	static char buffer[40];
	char *suffix = "EHz";
	double scale = 1e18;
	size_t i;

	for (i = 0; cpu_freq_scale[i].suffix; i++) {
		if (freq < cpu_freq_scale[i].threshold) {
			suffix = cpu_freq_scale[i].suffix;
			scale = cpu_freq_scale[i].scale;
			break;
		}
	}

	snprintf(buffer, sizeof(buffer), "%.2f %s",
		freq / scale, suffix);

	return buffer;
}

/*
 *  get_int32()
 *	parse an integer, return next non-digit char found
 */
static int get_int32(FILE *fp, int32_t *val)
{
	bool gotdigit = false;
	int ch;

	*val = 0;

	while ((ch = fgetc(fp)) != EOF) {
		if (isdigit(ch)) {
			gotdigit = true;
			*val = ((*val) * 10) + (ch - '0');
		} else
			break;
	}
	if (!gotdigit)
		*val = -1;
	return ch;
}

/*
 *  cpus_online()
 *	determine number of CPUs online
 */
static char *cpus_online(void)
{
	FILE *fp;
	static char buffer[16];
	uint32_t cpus = 0;

	fp = fopen("/sys/devices/system/cpu/online", "r");
	if (!fp)
		return "unknown";

	for (;;) {
		int ch;
		int32_t n1;

		ch = get_int32(fp, &n1);
		if (ch == '-') {
			int32_t n2;

			ch = get_int32(fp, &n2);
			if (n2 > -1) {
				uint32_t range = n2 - n1 + 1;
				if (range > 0)
					cpus += range;
			}
			n1 = -1;
			/* next char must bte EOF or , */
		}
		if (ch == EOF || ch == '\n') {
			if (n1 > -1)
				cpus++;
			break;
		}
		if (ch == ',') {
			if (n1 > -1)
				cpus++;
			continue;
		} 
		fclose(fp);
		return "unknown";
	}
	fclose(fp);
	snprintf(buffer, sizeof(buffer), "%" PRId32, cpus);

	return buffer;
}

/*
 *  load_average()
 *	get current load average stats
 */
static char *load_average(void)
{
	FILE *fp;

	fp = fopen("/proc/loadavg", "r");
	if (fp) {
		float l1, l5, l10;
		int ret;

		ret = fscanf(fp, "%10f %10f %10f", &l1, &l5, &l10);
		(void)fclose(fp);

		if (ret == 3) {
			static char buffer[64];
			snprintf(buffer, sizeof(buffer),
				"%.2f %.2f %.2f", l1, l5, l10);
			return buffer;
		}
	}
	return "unknown";
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	printf(APP_NAME ", version " VERSION "\n\n"
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
		" -x show extra stats (load average, avg cpu freq, etc)\n");
}

int main(int argc, char **argv)
{
	cpu_stat_t **cpu_stats_old, **cpu_stats_new, **cpu_stats_tmp;
	struct sigaction new_action;
	proc_stat_t proc_stats[2];
	proc_stat_t *proc_stat_old, *proc_stat_new, *proc_stat_tmp, proc_stat_delta;
	uint32_t max_cpus = sysconf(_SC_NPROCESSORS_CONF);
	double duration_secs = 1.0;
	double time_start, time_now;
	int64_t count = 1, t = 1;
	uint64_t nr_ticks, total_ticks = 0;
	int32_t n_lines = -1;
	uint32_t samples = 0;
	bool forever = true;
	int i;


	clock_ticks = (uint64_t)sysconf(_SC_CLK_TCK);

	for (;;) {
		int c = getopt(argc, argv, "acdDghiln:qr:sSt:Tp:x");
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
				fprintf(stderr, "Invalid value for -n option\n");
				exit(EXIT_FAILURE);
			}
			if (n_lines < 1) {
				fprintf(stderr,
					"-n option must be greater than 0\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'p':
			errno = 0;
			opt_pid = strtol(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr,
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
				fprintf(stderr,
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
		default:
			show_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (count_bits(opt_flags & OPT_CMD_ALL) > 1) {
		fprintf(stderr, "Cannot have -c, -l, -s at same time.\n");
		exit(EXIT_FAILURE);
	}
	if (optind < argc) {
		duration_secs = atof(argv[optind++]);
		if (duration_secs < 0.1) {
			fprintf(stderr, "Duration must 0.5 or more\n");
			exit(EXIT_FAILURE);
		}
	}
	if (optind < argc) {
		forever = false;
		errno = 0;
		count = (int64_t)strtoll(argv[optind++], NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid value for count\n");
			exit(EXIT_FAILURE);
		}
		if (count < 1) {
			fprintf(stderr, "Count must be greater than 0\n");
			exit(EXIT_FAILURE);
		}
	}
	opt_threshold *= duration_secs;

	memset(&new_action, 0, sizeof(new_action));
	for (i = 0; signals[i] != -1; i++) {
		new_action.sa_handler = handle_sig;
		sigemptyset(&new_action.sa_mask);
		new_action.sa_flags = 0;

		if (sigaction(signals[i], &new_action, NULL) < 0) {
			fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	cpu_stats_old = calloc(TABLE_SIZE, sizeof(cpu_stat_t*));
	cpu_stats_new = calloc(TABLE_SIZE, sizeof(cpu_stat_t*));
	if (cpu_stats_old == NULL || cpu_stats_new == NULL) {
		fprintf(stderr, "Cannot allocate CPU statistics tables\n");
		exit(EXIT_FAILURE);
	}
	proc_stat_old = &proc_stats[0];
	proc_stat_new = &proc_stats[1];
	time_now = time_start = gettime_to_double();
	get_cpustats(cpu_stats_old, time_now);
	get_proc_stat(proc_stat_old);
	nr_ticks = get_ticks();

	while (!stop_cpustat && (forever || count--)) {
		struct timeval tv;
		double secs, duration = duration_secs, right_now;

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
			t++;
		}
		double_to_timeval(secs, &tv);
		if (select(0, NULL, NULL, NULL, &tv) < 0) {
			if (errno == EINTR) {
				stop_cpustat = true;
			} else {
				fprintf(stderr,
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
		get_proc_stat(proc_stat_new);

		proc_stat_diff(proc_stat_old, proc_stat_new, &proc_stat_delta);
		if (opt_flags & OPT_EXTRA_STATS) {
			double avg_cpu_freq = cpu_freq_average(max_cpus);
			printf("Load Avg %s, Freq Avg. %s, %s CPUs online\n",
				load_average(),
				cpu_freq_format(avg_cpu_freq),
				cpus_online());
			proc_stat_dump(&proc_stat_delta);
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
		putchar('\n');
	}

	time_now = gettime_to_double();
	samples_dump(csv_results, time_now - time_start, time_now, nr_ticks, total_ticks, samples);
	if (opt_flags & OPT_DISTRIBUTION) {
		samples_distribution(nr_ticks);
		cpu_distribution(time_now - time_start, nr_ticks);
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
