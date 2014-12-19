/*
 * Copyright (C) 2011-2014 Canonical
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

#define APP_NAME	"cpustat"
#define TABLE_SIZE	(32999)		/* Should be a prime */
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

/* Generic linked list */
typedef struct link {
	void *data;			/* Data in list */
	struct link *next;		/* Next item in list */
} link_t;

/* Generic list header */
typedef struct {
	link_t	*head;			/* Head of list */
	link_t	*tail;			/* Tail of list */
	size_t	length;			/* Length of list */
} list_t;

typedef void (*list_link_free_t)(void *);

/* per process cpu information */
typedef struct {
	pid_t		pid;		/* Process ID */
	char 		*comm;		/* Name of process/kernel task */
	char		*cmdline;	/* Full name of process cmdline */
	char		*ident;		/* Pid + comm identifier */
	bool		kernel_thread;	/* true if a kernel thread */
	uint64_t	total;		/* Total number of CPU ticks */
} cpu_info_t;

/* CPU utilisation stats */
typedef struct cpu_stat {
	uint64_t	utime;		/* User time */
	uint64_t	stime;		/* System time */
	int64_t		delta;		/* Total Change in CPU ticks since last time */
	int64_t		udelta;		/* Change in user time */
	int64_t		sdelta;		/* Change in system time */
	bool		old;		/* Existing task, not a new one */
	cpu_info_t	*info;		/* CPU info */
	struct cpu_stat *next;		/* Next cpu stat in hash table */
	struct cpu_stat *sorted_usage_next;/* Next CPU stat in CPU usage sorted list */
} cpu_stat_t;

/* sample delta item as an element of the sample_delta_list_t */
typedef struct sample_delta_item {
	unsigned long	delta;		/* difference in CPU ticks between old and new */
	cpu_info_t	*info;		/* CPU info this refers to */
} sample_delta_item_t;

/* list of sample_delta_items */
typedef struct sample_delta_list {
	struct timeval	whence;		/* when the sample was taken */
	list_t		list;
} sample_delta_list_t;

static list_t cpu_info_list;		/* cache list of cpu_info */
static list_t sample_list;		/* list of samples, sorted in sample time order */
static char *csv_results;		/* results in comma separated values */
static volatile bool stop_cpustat = false;	/* set by sighandler */
static double opt_threshold;		/* ignore samples with CPU usage deltas less than this */
static unsigned int opt_flags;		/* option flags */
static unsigned long clock_ticks;	/* number of clock ticks per second */
static pid_t opt_pid = -1;		/* PID to match against, -p option */

/*
 *  timeval_sub()
 *	timeval a - b
 */
static struct timeval timeval_sub(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret, _b;

	_b.tv_sec = b->tv_sec;
	_b.tv_usec = b->tv_usec;

	if (a->tv_usec < _b.tv_usec) {
		suseconds_t nsec = ((_b.tv_usec - a->tv_usec) / 1000000) + 1;
		_b.tv_sec += nsec;
		_b.tv_usec -= (1000000 * nsec);
	}
	if (a->tv_usec - _b.tv_usec > 1000000) {
		suseconds_t nsec = (a->tv_usec - _b.tv_usec) / 1000000;
		_b.tv_sec -= nsec;
		_b.tv_usec += (1000000 * nsec);
	}

	ret.tv_sec = a->tv_sec - _b.tv_sec;
	ret.tv_usec = a->tv_usec - _b.tv_usec;

	return ret;
}

/*
 *  timeval_sub()
 *	timeval a + b
 */
static struct timeval timeval_add(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret;

	ret.tv_sec = a->tv_sec + b->tv_sec;
	ret.tv_usec = a->tv_usec + b->tv_usec;
	if (ret.tv_usec > 1000000) {
		int nsec = (ret.tv_usec / 1000000);
		ret.tv_sec += nsec;
		ret.tv_usec -= (1000000 * nsec);
	}

	return ret;
}

/*
 *  timeval_double
 *	timeval to a double
 */
static inline double timeval_double(const struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  list_init()
 *	initialise list
 */
static inline void list_init(list_t *list)
{
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;
}

/*
 *  list_append()
 *	add new data to end of the list
 */
static link_t *list_append(list_t *list, void *data)
{
	link_t *link;

	if ((link = calloc(sizeof(link_t), 1)) == NULL) {
		fprintf(stderr, "Cannot allocate list link\n");
		exit(EXIT_FAILURE);
	}
	link->data = data;
	
	if (list->head == NULL) {
		list->head = link;
	} else {
		list->tail->next = link;
	}
	list->tail = link;
	list->length++;

	return link;
}

/* 
 *  list_free()
 *	free list and items in list using freefunc callback
 */
static void list_free(list_t *list, list_link_free_t freefunc)
{
	link_t	*link, *next;

	if (list == NULL)
		return;

	for (link = list->head; link; link = next) {
		next = link->next;
		if (link->data && freefunc)
			freefunc(link->data);
		free(link);
	}
}

/*
 *  handle_sigint()
 *      catch SIGINT and flag a stop
 */
static void handle_sigint(int dummy)
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
 *  sample_delta_free()
 *	free sample delta item
 */
static void sample_delta_free(void *data)
{
	sample_delta_list_t *sdl = (sample_delta_list_t*)data;

	list_free(&sdl->list, free);
	free(sdl);
}

/*
 *  samples_free()
 *	free collected samples
 */
static void samples_free(void)
{
	list_free(&sample_list, sample_delta_free);
}

/*
 *  sample_add()
 *	add a cpu_stat's delta and info field to a list at time position whence
 */
static void sample_add(cpu_stat_t *cpu_stat, struct timeval *whence)
{
	link_t	*link;
	bool	found = false;
	sample_delta_list_t *sdl = NULL;
	sample_delta_item_t *sdi;

	if (csv_results == NULL)	/* No need if not request */
		return;

	for (link = sample_list.head; link; link = link->next) {
		sdl = (sample_delta_list_t*)link->data;
		if ((sdl->whence.tv_sec == whence->tv_sec) &&
		    (sdl->whence.tv_usec == whence->tv_usec)) {
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
		sdl->whence = *whence;
		list_append(&sample_list, sdl);
	}

	/* Now append the sdi onto the list */
	if ((sdi = calloc(1, sizeof(sample_delta_item_t))) == NULL) {
		fprintf(stderr, "Cannot allocate sample delta item\n");
		exit(EXIT_FAILURE);
	}
	sdi->delta = cpu_stat->delta;
	sdi->info  = cpu_stat->info;

	list_append(&sdl->list, sdi);
}

/*
 *  sample_find()
 *	scan through a sample_delta_list for cpu info, return NULL if not found
 */
static inline sample_delta_item_t *sample_find(sample_delta_list_t *sdl, cpu_info_t *info)
{
	link_t *link;

	for (link = sdl->list.head; link; link = link->next) {
		sample_delta_item_t *sdi = (sample_delta_item_t*)link->data;
		if (sdi->info == info)
			return sdi;
	}
	return NULL;
}

/*
 * info_compare_total()
 *	used by qsort to sort array in CPU consumed ticks total order
 */
static int info_compare_total(const void *item1, const void *item2)
{
	cpu_info_t **info1 = (cpu_info_t **)item1;
	cpu_info_t **info2 = (cpu_info_t **)item2;

	if ((*info2)->total == (*info1)->total)
		return 0;

	return ((*info2)->total > (*info1)->total) ? 1 : -1;
}

/*
 *  samples_dump()
 *	dump out samples to file
 */
static void samples_dump(const char *filename, struct timeval *duration)
{
	sample_delta_list_t	*sdl;
	cpu_info_t **sorted_cpu_infos;
	link_t	*link;
	size_t i = 0, n = cpu_info_list.length;
	FILE *fp;
	unsigned long nr_ticks = clock_ticks;

	double dur = timeval_double(duration);
	bool dur_zero = (duration->tv_sec == 0) && (duration->tv_usec == 0);

	if (opt_flags & OPT_TICKS_ALL)
		nr_ticks *= sysconf(_SC_NPROCESSORS_CONF);

	if (filename == NULL)
		return;

	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot write to file %s\n", filename);
		return;
	}

	if ((sorted_cpu_infos = calloc(n, sizeof(cpu_info_t*))) == NULL) {
		fprintf(stderr, "Cannot allocate buffer for sorting cpu_infos\n");
		exit(EXIT_FAILURE);
	}

	/* Just want the CPUs with some non-zero total */
	for (n = 0, link = cpu_info_list.head; link; link = link->next) {
		cpu_info_t *info = (cpu_info_t*)link->data;
		if (info->total > 0)
			sorted_cpu_infos[n++] = info;
	}

	qsort(sorted_cpu_infos, n, sizeof(cpu_info_t *), info_compare_total);

	fprintf(fp, "Task:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%s (%d)", sorted_cpu_infos[i]->comm,
			sorted_cpu_infos[i]->pid);
	fprintf(fp, "\n");

	for (i = 0; i < n; i++)
		fprintf(fp, ",%" PRIu64, sorted_cpu_infos[i]->total);
	fprintf(fp, "\n");

	for (link = sample_list.head; link; link = link->next) {
		sdl = (sample_delta_list_t*)link->data;
		fprintf(fp, "%f", timeval_double(&sdl->whence));

		/* Scan in CPU info order to be consistent for all sdl rows */
		for (i = 0; i < n; i++) {
			sample_delta_item_t *sdi = sample_find(sdl, sorted_cpu_infos[i]);
			if (sdi)
				fprintf(fp,",%f",
					dur_zero ? 0 : 100.0 * (double)sdi->delta / (dur * (double)nr_ticks) );
			else
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
static cpu_info_t *cpu_info_find(cpu_info_t *new_info)
{
	link_t *link;
	cpu_info_t *info;

	for (link = cpu_info_list.head; link; link = link->next) {
		info = (cpu_info_t*)link->data;
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

	list_append(&cpu_info_list, info);

	return info;
}

/*
 *  cpu_info_free()
 *	free cpu_info and it's elements
 */
static void cpu_info_free(void *data)
{
	cpu_info_t *info = (cpu_info_t*)data;

	free(info->comm);
	free(info->ident);
	free(info);
}

/*
 *  cpu_info_free
 *	free up all unique cpu infos
 */
static void cpu_info_list_free(void)
{
	list_free(&cpu_info_list, cpu_info_free);
}

/*
 *  hash_pjw()
 *	Hash a string, from Aho, Sethi, Ullman, Compiling Techniques.
 */
static unsigned long hash_pjw(char *str)
{
  	unsigned long h = 0;

	while (*str) {
		unsigned long g;
		h = (h << 4) + (*str);
		if (0 != (g = h & 0xf0000000)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		str++;
	}

  	return h % TABLE_SIZE;
}

/*
 *  cpu_stat_free_contents()
 *	Free CPU info from a hash table
 */
static void cpu_stat_free_contents(
	cpu_stat_t *cpu_stats[])	/* CPU stat hash table */
{
	int i;

	for (i=0; i<TABLE_SIZE; i++) {
		cpu_stat_t *cs = cpu_stats[i];

		while (cs) {
			cpu_stat_t *next = cs->next;
			free(cs);

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
static void cpu_stat_add(
	cpu_stat_t *cpu_stats[],	/* CPU stat hash table */
	const pid_t pid,		/* PID of task */
	char *comm,			/* Name of task */
	const uint64_t utime,
	const uint64_t stime)
{
	char ident[1024];
	cpu_stat_t *cs;
	cpu_stat_t *cs_new;
	cpu_info_t info;
	unsigned long h;

	snprintf(ident, sizeof(ident), "%d:%s", pid, comm);

	h = hash_pjw(ident);
	cs = cpu_stats[h];

	for (cs = cpu_stats[h]; cs; cs = cs->next) {
		if (strcmp(cs->info->ident, ident) == 0) {
			cs->utime += utime;
			cs->stime += stime;
			return;
		}
	}
	/* Not found, it is new! */

	if ((cs_new = calloc(1, sizeof(cpu_stat_t))) == NULL) {
		fprintf(stderr, "Out of memory allocating a cpu stat\n");
		exit(1);
	}

	info.pid = pid;
	info.comm = comm;
	info.cmdline = get_pid_cmdline(pid);
	info.kernel_thread = (info.cmdline == NULL);
	info.ident = ident;

	cs_new->utime = utime;
	cs_new->stime = stime;
	cs_new->info = cpu_info_find(&info);
	cs_new->next = cpu_stats[h];
	cs_new->sorted_usage_next = NULL;

	cpu_stats[h] = cs_new;
}

/*
 *  cpu_stat_find()
 *	find a CPU stat (needle) in a CPU stat hash table (haystack)
 */
static cpu_stat_t *cpu_stat_find(
	cpu_stat_t *haystack[],		/* CPU stat hash table */
	cpu_stat_t *needle)		/* CPU stat to find */
{
	cpu_stat_t *ts;
	char ident[1024];

	snprintf(ident, sizeof(ident), "%d:%s",
		needle->info->pid, needle->info->comm);

	for (ts = haystack[hash_pjw(ident)]; ts; ts = ts->next)
		if (strcmp(ts->info->ident, ident) == 0)
			return ts;

	return NULL;	/* no success */
}

/*
 *  cpu_stat_sort_freq_add()
 *	add a CPU stat to a sorted list of CPU stats
 */
static void cpu_stat_sort_freq_add(
	cpu_stat_t **sorted,		/* CPU stat sorted list */
	cpu_stat_t *new)		/* CPU stat to add */
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
	struct timeval *duration,	/* time between each sample */
	const int n_lines,		/* number of lines to output */
	struct timeval *whence,		/* nth sample */
	cpu_stat_t *cpu_stats_old[],	/* old CPU stats samples */
	cpu_stat_t *cpu_stats_new[])	/* new CPU stats samples */
{
	int i;
	double dur = timeval_double(duration);
	cpu_stat_t *sorted = NULL;
	unsigned long nr_ticks = clock_ticks;

	if (opt_flags & OPT_TICKS_ALL)
		nr_ticks *= sysconf(_SC_NPROCESSORS_CONF);

	for (i=0; i<TABLE_SIZE; i++) {
		cpu_stat_t *cs;

		for (cs = cpu_stats_new[i]; cs; cs = cs->next) {
			cpu_stat_t *found =
				cpu_stat_find(cpu_stats_old, cs);
			if (found) {
				cs->udelta = cs->utime - found->utime;
				cs->sdelta = cs->stime - found->stime;
				cs->delta  = cs->udelta + cs->sdelta;
				if (cs->delta >= (int64_t)opt_threshold) {
					cs->old = true;
					cpu_stat_sort_freq_add(&sorted, cs);
					sample_add(cs, whence);
					found->info->total += cs->delta;
				}
			} else {
				cs->delta = cs->udelta = cs->sdelta = 0;
				if (cs->delta >= (int64_t)opt_threshold) {
					cs->old = false;
					cpu_stat_sort_freq_add(&sorted, cs);
					sample_add(cs, whence);
				}
			}
		}
	}

	if (!(opt_flags & OPT_QUIET)) {
		int j = 0;
		double cpu_u_total = 0.0, cpu_s_total = 0.0;

		printf("  %%CPU   %%USR   %%SYS   PID   Task\n");
		while (sorted) {
			double cpu_u_usage =
				100.0 * (double)sorted->udelta /
				(dur * (double)(nr_ticks));
			double cpu_s_usage =
				100.0 * (double)sorted->sdelta /
				(dur * (double)(nr_ticks));
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
static void get_cpustats(cpu_stat_t *cpu_stats[])	/* hash table to populate */
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
			cpu_stat_add(cpu_stats, pid, comm, utime, stime);
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
		"Usage: " APP_NAME " [optionns] [duration] [count]\n"
		" -h help\n"
		" -a calculate CPU utilisation based on all the CPU ticks rather than per CPU tick\n"
		" -c get command name from processes comm field\n"
		" -d strip directory basename off command information\n"
		" -i ignore " APP_NAME " in the statistics\n"
		" -l show long (full) command information\n"
		" -n specifies number of tasks to display\n"
		" -p just show utilisation for a specified PID\n"
		" -q run quietly, useful with option -r\n"
		" -r specifies a comma separated values output file to dump samples into\n"
		" -s show short command information\n"
		" -t specifies a task tick count threshold where samples less than this are ignored\n"
		" -T show total CPU utilisation statistics\n");
}

int main(int argc, char **argv)
{
	cpu_stat_t **cpu_stats_old, **cpu_stats_new, **tmp;
	double duration_secs = 1.0;
	int count = 1;
	int n_lines = -1;
	bool forever = true;
	struct timeval tv1, tv2, duration, whence;

	list_init(&cpu_info_list);
	list_init(&sample_list);

	clock_ticks = sysconf(_SC_CLK_TCK);

	for (;;) {
		int c = getopt(argc, argv, "acdhiln:qr:st:Tp:");
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
			n_lines = strtol(optarg, NULL, 10);
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
		count = strtol(argv[optind++], NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid value for count\n");
			exit(EXIT_FAILURE);
		}
		if (count < 1) {
			fprintf(stderr, "Count must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	duration.tv_sec = (time_t)duration_secs;
	duration.tv_usec = (suseconds_t)(duration_secs * 1000000.0) - (duration.tv_sec * 1000000);
	opt_threshold *= duration_secs;

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root privileges to read /proc/$pid/stat\n",
			APP_NAME);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, &handle_sigint);

	cpu_stats_old = calloc(TABLE_SIZE, sizeof(cpu_stat_t*));
	cpu_stats_new = calloc(TABLE_SIZE, sizeof(cpu_stat_t*));

	if (cpu_stats_old == NULL || cpu_stats_new == NULL) {
		fprintf(stderr, "Cannot allocate CPU statistics tables\n");
		exit(EXIT_FAILURE);
	}

	if (gettimeofday(&tv1, NULL) < 0) {
		fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
			errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	get_cpustats(cpu_stats_old);

	whence.tv_sec = 0;
	whence.tv_usec = 0;

	while (!stop_cpustat && (forever || count--)) {
		struct timeval tv;
		int ret;

		if (gettimeofday(&tv2, NULL) < 0) {
			fprintf(stderr, "gettimeofday failed: errno=%d (%s)\n",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		tv = timeval_add(&duration, &whence);
		tv = timeval_add(&tv, &tv1);
		tv2 = tv = timeval_sub(&tv, &tv2);

		/* Play catch-up, probably been asleep */
		if (tv.tv_sec < 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			tv2 = tv;
		}
		ret = select(0, NULL, NULL, NULL, &tv2);
		if (ret < 0) {
			if (errno == EINTR) {
				duration = timeval_sub(&tv, &tv2);
				stop_cpustat = true;
			} else {
				fprintf(stderr, "select failed: errno=%d (%s)\n",
					errno, strerror(errno));
				break;
			}
		}

		get_cpustats(cpu_stats_new);
		cpu_stat_diff(&duration, n_lines, &whence,
			cpu_stats_old, cpu_stats_new);
		cpu_stat_free_contents(cpu_stats_old);

		tmp             = cpu_stats_old;
		cpu_stats_old = cpu_stats_new;
		cpu_stats_new = tmp;

		whence = timeval_add(&duration, &whence);
	}

	samples_dump(csv_results, &duration);

	cpu_stat_free_contents(cpu_stats_old);
	cpu_stat_free_contents(cpu_stats_new);
	free(cpu_stats_old);
	free(cpu_stats_new);
	samples_free();
	cpu_info_list_free();

	exit(EXIT_SUCCESS);
}
