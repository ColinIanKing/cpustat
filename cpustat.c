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
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>

#define APP_NAME	"cpustat"
#define TABLE_SIZE	(2411)		/* Should be a prime */
#define OPT_QUIET	(0x00000001)
#define OPT_IGNORE_SELF	(0x00000002)
#define	OPT_CMD_SHORT	(0x00000004)
#define OPT_CMD_LONG	(0x00000008)
#define OPT_CMD_COMM	(0x00000010)
#define OPT_CMD_ALL	(OPT_CMD_SHORT | OPT_CMD_LONG | OPT_CMD_COMM)
#define OPT_DIRNAME_STRIP (0x00000020)
#define OPT_TICKS_ALL	(0x00000040)
#define OPT_TOTAL	(0x00000080)
#define OPT_MATCH_PID	(0x00000100)
#define OPT_TIMESTAMP	(0x00000200)


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
	pid_t		pid;		/* Process ID */
	char 		*comm;		/* Name of process/kernel task */
	char		*cmdline;	/* Full name of process cmdline */
	char		*ident;		/* Pid + comm identifier */
	bool		kernel_thread;	/* true if a kernel thread */
	uint64_t	total;		/* Total number of CPU ticks */
	struct cpu_info_t *hash_next;	/* Next cpu info in hash */
	struct cpu_info_t *list_next;	/* Next cpu info in list */
} cpu_info_t;

/* CPU utilisation stats */
typedef struct cpu_stat {
	uint64_t	utime;		/* User time */
	uint64_t	stime;		/* System time */
	double		time;		/* Wall clock time */
	int64_t		delta;		/* Total Change in CPU ticks since last time */
	int64_t		udelta;		/* Change in user time */
	int64_t		sdelta;		/* Change in system time */
	double		time_delta;	/* Wall clock time delta */
	bool		old;		/* Existing task, not a new one */
	cpu_info_t	*info;		/* CPU info */
	struct cpu_stat *next;		/* Next cpu stat in hash table */
	struct cpu_stat *sorted_usage_next;/* Next CPU stat in CPU usage sorted list */
} cpu_stat_t;

/* sample delta item as an element of the sample_delta_list_t */
typedef struct sample_delta_item {
	int64_t		delta;		/* difference in CPU ticks between old and new */
	double		time_delta;	/* difference in time between old and new */
	cpu_info_t	*info;		/* CPU info this refers to */
	struct sample_delta_item *next;	/* Next in the list */
} sample_delta_item_t;

/* list of sample_delta_items */
typedef struct sample_delta_list {
	double		whence;		/* when the sample was taken */
	struct sample_delta_item *sample_delta_item_list;
	struct sample_delta_list *next;	/* next item in sample delta list */
} sample_delta_list_t;

static cpu_stat_t *cpu_stat_free_list;	/* List of free'd cpu stats */
static cpu_info_t *cpu_info_hash[TABLE_SIZE];
					/* hash of cpu_info */
static cpu_info_t *cpu_info_list;	/* cache list of cpu_info */
static size_t cpu_info_list_length;	/* cpu_info_list length */
static sample_delta_list_t *sample_delta_list;
					/* list of samples, sorted in sample time order */
static char *csv_results;		/* results in comma separated values */
static volatile bool stop_cpustat = false;	/* set by sighandler */
static double opt_threshold;		/* ignore samples with CPU usage deltas less than this */
static unsigned int opt_flags;		/* option flags */
static unsigned long clock_ticks;	/* number of clock ticks per second */
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
static inline struct timeval double_to_timeval(const double val)
{
	struct timeval tv;

	tv.tv_sec = val;
	tv.tv_usec = (val - (time_t)val) * 1000000.0;

	return tv;
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
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		(void)close(fd);
		return NULL;
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
		return strdup(basename(buffer));

	return strdup(buffer);
}

/*
 *  samples_free()
 *	free collected samples
 */
static void samples_free(void)
{
	sample_delta_list_t *sdl = sample_delta_list;

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

	if (csv_results == NULL)	/* No need if not request */
		return;

	for (sdl = sample_delta_list; sdl; sdl = sdl->next) {
		if (sdl->whence == whence) {
			found = true;
			break;
		}
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
		sdl->next = sample_delta_list;
		sample_delta_list = sdl;
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
 *	round duration to nearest 1/20th second
 */
static inline double duration_round(const double duration)
{
        return floor((duration * 20.0) + 0.5) / 20.0;
}

/*
 *  samples_dump()
 *	dump out samples to file
 */
static void samples_dump(
	const char *const filename)		/* file to dump samples */
{
	sample_delta_list_t	*sdl;
	cpu_info_t **sorted_cpu_infos;
	cpu_info_t *cpu_info;
	size_t i = 0, n;
	FILE *fp;
	unsigned long nr_ticks = clock_ticks;
	double first_time = -1.0;

	if (opt_flags & OPT_TICKS_ALL)
		nr_ticks *= sysconf(_SC_NPROCESSORS_CONF);

	if (filename == NULL)
		return;

	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot write to file %s\n", filename);
		return;
	}

	if ((sorted_cpu_infos = calloc(cpu_info_list_length, sizeof(cpu_info_t*))) == NULL) {
		fprintf(stderr, "Cannot allocate buffer for sorting cpu_infos\n");
		exit(EXIT_FAILURE);
	}

	/* Just want the CPUs with some non-zero total */
	for (n = 0, cpu_info = cpu_info_list; cpu_info; cpu_info = cpu_info->list_next) {
		if (cpu_info->total > 0)
			sorted_cpu_infos[n++] = cpu_info;
	}

	qsort(sorted_cpu_infos, n, sizeof(cpu_info_t *), info_compare_total);

	fprintf(fp, "Task:%s", (opt_flags & OPT_TIMESTAMP) ? "," : "");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%s (%d)", sorted_cpu_infos[i]->comm,
			sorted_cpu_infos[i]->pid);
	fprintf(fp, "\n");

	fprintf(fp, "Ticks:%s", (opt_flags & OPT_TIMESTAMP) ? "," : "");
	
	for (i = 0; i < n; i++)
		fprintf(fp, ",%" PRIu64, sorted_cpu_infos[i]->total);
	fprintf(fp, "\n");

	for (sdl = sample_delta_list; sdl; sdl = sdl->next) {
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
			sample_delta_item_t *sdi = sample_find(sdl, sorted_cpu_infos[i]);
			if (sdi) {
				double duration = duration_round(sdi->time_delta);
				fprintf(fp,",%f",
					(duration == 0.0) ? 0.0 : 
					100.0 * (double)sdi->delta / (duration * (double)nr_ticks));
			} else
				fprintf(fp,", ");
		}
		fprintf(fp, "\n");
	}

	free(sorted_cpu_infos);
	(void)fclose(fp);
}

/*
 *  cpu_info_find()
 *	try to find existing cpu info in cache, and to the cache
 *	if it is new.
 */
static cpu_info_t OPTIMIZE3 HOT *cpu_info_find(const cpu_info_t *const new_info, const uint32_t hash)
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
	info->comm = strdup(new_info->comm);
	info->kernel_thread = new_info->kernel_thread;

	if ((new_info->cmdline == NULL) || (opt_flags & OPT_CMD_COMM))
		info->cmdline = info->comm;
	else
		info->cmdline = new_info->cmdline;

	info->ident = strdup(new_info->ident);

	if (info->comm == NULL ||
	    info->cmdline == NULL ||
	    info->ident == NULL) {
		fprintf(stderr, "Out of memory allocating a cpu stat fields\n");
		exit(1);
	}

	/* Does not exist in list, append it */
	info->list_next = cpu_info_list;
	cpu_info_list = info;
	
	return info;
}

/*
 *  cpu_info_free()
 *	free cpu_info and it's elements
 */
static void cpu_info_free(void *const data)
{
	cpu_info_t *info = (cpu_info_t*)data;

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
	const uint64_t utime,
	const uint64_t stime)
{
	char ident[1024];
	cpu_stat_t *cs;
	cpu_stat_t *cs_new;
	cpu_info_t info;
	uint32_t h;

	snprintf(ident, sizeof(ident), "%x%s", pid, comm);

	h = hash_djb2a(ident);
	cs = cpu_stats[h];

	for (cs = cpu_stats[h]; cs; cs = cs->next) {
		if (strcmp(cs->info->ident, ident) == 0) {
			cs->utime += utime;
			cs->stime += stime;
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
			fprintf(stderr, "Out of memory allocating a cpu stat\n");
			exit(1);
		}
	}

	info.pid = pid;
	info.comm = (char *)comm;
	info.cmdline = get_pid_cmdline(pid);
	info.kernel_thread = (info.cmdline == NULL);
	info.ident = ident;

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
 *	stats.  We are interested in just current and new CPU stats, not ones that
 *	silently die
 */
static void cpu_stat_diff(
	const double duration,			/* time between each sample */
	const int32_t n_lines,			/* number of lines to output */
	const double time_now,			/* time right now */
	cpu_stat_t *const cpu_stats_old[],	/* old CPU stats samples */
	cpu_stat_t *const cpu_stats_new[])	/* new CPU stats samples */
{
	int i;
	cpu_stat_t *sorted = NULL;
	unsigned long nr_ticks = clock_ticks;

	if (opt_flags & OPT_TICKS_ALL)
		nr_ticks *= sysconf(_SC_NPROCESSORS_CONF);

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
					cpu_stat_sort_freq_add(&sorted, cs);
					sample_add(cs, time_now);
					found->info->total += cs->delta;
				}
			} else {
				cs->delta = cs->udelta = cs->sdelta = 0;
				cs->time_delta = duration;
				if (cs->delta >= (int64_t)opt_threshold) {
					cs->old = false;
					cpu_stat_sort_freq_add(&sorted, cs);
					sample_add(cs, time_now);
				}
			}
		}
	}

	if (!(opt_flags & OPT_QUIET)) {
		int32_t j = 0;
		double cpu_u_total = 0.0, cpu_s_total = 0.0;
		char ts[32];

		if (opt_flags & OPT_TIMESTAMP) {
			struct tm tm;

			get_tm(time_now, &tm);
			snprintf(ts, sizeof(ts), "  (%2.2d:%2.2d:%2.2d)",
				tm.tm_hour, tm.tm_min, tm.tm_sec);
		} else {
			*ts = '\0';
		}

		printf("  %%CPU   %%USR   %%SYS   PID   Task%s\n", ts);
		while (sorted) {
			double cpu_u_usage =
				100.0 * (double)sorted->udelta /
				(duration * (double)(nr_ticks));
			double cpu_s_usage =
				100.0 * (double)sorted->sdelta /
				(duration * (double)(nr_ticks));
			double cpu_t_usage = cpu_u_usage + cpu_s_usage;

			cpu_u_total += cpu_u_usage;
			cpu_s_total += cpu_s_usage;

			if ((n_lines == -1) || (j < n_lines)) {
				j++;
				if (cpu_t_usage > 0.0) {
					printf("%6.2f %6.2f %6.2f %5d %s%s%s\n",
						cpu_t_usage, cpu_u_usage, cpu_s_usage,
						sorted->info->pid,
						sorted->info->kernel_thread ? "[" : "",
						sorted->info->cmdline,
						sorted->info->kernel_thread ? "]" : "");
				}
			}
			sorted = sorted->sorted_usage_next;
		}
		if (opt_flags & OPT_TOTAL)
			printf("%6.2f %6.2f %6.2f Total\n",
				cpu_u_total + cpu_s_total, cpu_u_total, cpu_s_total);
		printf("\n");
	}
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
		pid_t pid;
		uint64_t utime;
		uint64_t stime;
		int n;

		if (!isdigit(entry->d_name[0]))
			continue;

		snprintf(filename, sizeof(filename), "/proc/%s/stat", entry->d_name);
		if ((fp = fopen(filename, "r")) == NULL)
			continue;

		/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */
		n = fscanf(fp, "%8d (%20[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
				"%20" SCNu64 "%20" SCNu64,
			&pid, comm, &utime, &stime);
		(void)fclose(fp);

		if ((opt_flags & OPT_IGNORE_SELF) && (my_pid == pid))
			continue;
		if ((opt_flags & OPT_MATCH_PID) && (opt_pid != pid))
			continue;

		if (n == 4)
			cpu_stat_add(cpu_stats, time_now, pid, comm, utime, stime);
	}

	(void)closedir(dir);
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
		" -T show total CPU utilisation statistics\n");
}

int main(int argc, char **argv)
{
	cpu_stat_t **cpu_stats_old, **cpu_stats_new, **tmp;
	double duration_secs = 1.0;
	int i;
	int64_t count = 1, t = 1;
	int32_t n_lines = -1;
	bool forever = true;
	double time_start, time_now;
	struct sigaction new_action;

	clock_ticks = sysconf(_SC_CLK_TCK);

	for (;;) {
		int c = getopt(argc, argv, "acdhiln:qr:sSt:Tp:");
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
				fprintf(stderr, "-n option must be greater than 0\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'p':
			errno = 0;
			opt_pid = strtol(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid value for -o option\n");
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
				fprintf(stderr, "-t threshold must be 0 or more.\n");
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
		if (duration_secs < 0.5) {
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

	time_now = time_start = gettime_to_double();

	get_cpustats(cpu_stats_old, time_now);

	while (!stop_cpustat && (forever || count--)) {
		struct timeval tv;
		double secs, duration = duration_secs, right_now;
		int ret;

		/* Timeout to wait for in the future for this sample */
		secs = time_start + ((double)t * duration_secs) - time_now;
		/* Play catch-up, probably been asleep */
		if (secs < 0.0) {
			t = ceil((time_now - time_start) / duration_secs);
			secs = time_start + ((double)t * duration_secs) - time_now;
			/* We don't get sane stats if the duration is too small */
			if (secs < 0.5)
				secs += duration_secs;
		} else {
			t++;
		}
		tv = double_to_timeval(secs);
		ret = select(0, NULL, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EINTR) {
				stop_cpustat = true;
			} else {
				fprintf(stderr, "select failed: errno=%d (%s)\n",
					errno, strerror(errno));
				break;
			}
		}
		right_now = gettime_to_double();
		duration = duration_round(right_now - time_now);
		time_now = right_now;
		get_cpustats(cpu_stats_new, time_now);
		cpu_stat_diff(duration, n_lines, time_now,
			cpu_stats_old, cpu_stats_new);
		cpu_stat_free_contents(cpu_stats_old);

		tmp           = cpu_stats_old;
		cpu_stats_old = cpu_stats_new;
		cpu_stats_new = tmp;
	}

	samples_dump(csv_results);

	cpu_stat_free_contents(cpu_stats_old);
	cpu_stat_free_contents(cpu_stats_new);
	free(cpu_stats_old);
	free(cpu_stats_new);
	samples_free();
	cpu_info_list_free();
	cpu_stat_list_free();

	exit(EXIT_SUCCESS);
}
