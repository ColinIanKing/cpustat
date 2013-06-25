/*
 * Copyright (C) 2011 Canonical
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <ctype.h>

#define APP_NAME	"cpustat"
#define TABLE_SIZE	(32999)		/* Should be a prime */
#define OPT_QUIET	(0x00000001)
#define OPT_IGNORE_SELF	(0x00000002)

typedef struct link {
	void *data;
	struct link *next;
} link_t;

typedef struct {
	link_t	*head;
	link_t	*tail;
	size_t	length;
} list_t;

typedef void (*list_link_free_t)(void *);

typedef struct {
	pid_t		pid;
	char 		*comm;		/* Name of process/kernel task */
	char		*ident;
	unsigned long	total;		/* Total number of CPU ticks */
} cpu_info_t;

typedef struct cpu_stat {
	unsigned long	utime;
	unsigned long	stime;
	unsigned long	delta;		/* Change in CPU ticks since last time */
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
	unsigned long		whence;	/* when the sample was taken */
	list_t			list;
} sample_delta_list_t;

static list_t cpu_info_list;			/* cache list of cpu_info */
static list_t sample_list;			/* list of samples, sorted in sample time order */
static char *csv_results;			/* results in comma separated values */
static volatile bool stop_cpustat = false;	/* set by sighandler */
static unsigned long opt_threshold;		/* ignore samples with CPU usage deltas less than this */
static unsigned int opt_flags;			/* option flags */
static unsigned long clock_ticks;

static inline void list_init(list_t *list)
{
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;
}

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
		list->tail = link;
	} else {
		list->tail->next = link;
		list->tail = link;
	}
	list->length++;

	return link;
}

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
	stop_cpustat = true;
}

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
static void sample_add(cpu_stat_t *cpu_stat, unsigned long whence)
{
	link_t	*link;
	bool	found = false;
	sample_delta_list_t *sdl = NULL;
	sample_delta_item_t *sdi;

	if (csv_results == NULL)	/* No need if not request */
		return;

	for (link = sample_list.head; link; link = link->next) {
		sdl = (sample_delta_list_t*)link->data;
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
static sample_delta_item_t inline *sample_find(sample_delta_list_t *sdl, cpu_info_t *info)
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

	return (*info2)->total - (*info1)->total;
}

static void samples_dump(const char *filename, const int duration)
{
	sample_delta_list_t	*sdl;
	cpu_info_t **sorted_cpu_infos;
	link_t	*link;
	int i = 0;
	size_t n = cpu_info_list.length;
	FILE *fp;
	unsigned long nr_ticks = sysconf(_SC_NPROCESSORS_CONF) * clock_ticks;

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
	for (i=0; i<n; i++)
		fprintf(fp, ",%s (%d)", sorted_cpu_infos[i]->comm, 
			sorted_cpu_infos[i]->pid);
	fprintf(fp, "\n");

	for (i=0; i<n; i++)
		fprintf(fp, ",%lu", sorted_cpu_infos[i]->total);
	fprintf(fp, "\n");

	for (link = sample_list.head; link; link = link->next) {
		sdl = (sample_delta_list_t*)link->data;
		fprintf(fp, "%lu", sdl->whence);

		/* Scan in CPU info order to be consistent for all sdl rows */
		for (i=0; i<n; i++) {
			sample_delta_item_t *sdi = sample_find(sdl, sorted_cpu_infos[i]);
			if (sdi)
				fprintf(fp,",%f", 100.0 * (double)sdi->delta / (double)(duration * nr_ticks));
			else
				fprintf(fp,", ");
		}
		fprintf(fp, "\n");
	}

	free(sorted_cpu_infos);
	fclose(fp);
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
	info->ident = strdup(new_info->ident);

	if (info->comm == NULL ||
	    info->ident == NULL) {
		fprintf(stderr, "Out of memory allocating a cpu stat fields\n");
		exit(1);
	}

	/* Does not exist in list, append it */

	list_append(&cpu_info_list, info);

	return info;
}

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
  	unsigned long h=0, g;

	while (*str) {
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
	pid_t pid,			/* PID of task */
	char *comm,			/* Name of task */
	unsigned long utime,
	unsigned long stime)
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

	if ((cs_new = malloc(sizeof(cpu_stat_t))) == NULL) {
		fprintf(stderr, "Out of memory allocating a cpu stat\n");
		exit(1);
	}

	info.pid = pid;
	info.comm = comm;
	info.ident = ident;

	cs_new->utime = utime;
	cs_new->stime = stime;
	cs_new->info = cpu_info_find(&info);
	cs_new->next  = cpu_stats[h];
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
	const int duration,		/* time between each sample */
	const int n_lines,		/* number of lines to output */
	unsigned long whence,		/* nth sample */
	cpu_stat_t *cpu_stats_old[],	/* old CPU stats samples */
	cpu_stat_t *cpu_stats_new[])	/* new CPU stats samples */
{
	int i;
	int j = 0;

	cpu_stat_t *sorted = NULL;

	unsigned long nr_ticks = sysconf(_SC_NPROCESSORS_CONF) * clock_ticks;

	for (i=0; i<TABLE_SIZE; i++) {
		cpu_stat_t *cs;

		for (cs = cpu_stats_new[i]; cs; cs = cs->next) {
			cpu_stat_t *found =
				cpu_stat_find(cpu_stats_old, cs);
			if (found) {
				cs->delta = (cs->utime + cs->stime) - (found->utime + found->stime);
				if (cs->delta >= opt_threshold) {
					cs->old = true;
					cpu_stat_sort_freq_add(&sorted, cs);
					sample_add(cs, whence);
					found->info->total += cs->delta;
				}
			} else {
				cs->delta = 0;
				if (cs->delta >= opt_threshold) {
					cs->old = false;
					cpu_stat_sort_freq_add(&sorted, cs);
					sample_add(cs, whence);
				}
			}
		}
	}

	if (!(opt_flags & OPT_QUIET)) {
		printf(" %%CPU   PID   Task\n");

		while (sorted) {
			if ((n_lines == -1) || (j < n_lines)) {
				j++;
				double cpu_usage = 
					100.0 * (double)sorted->delta / 
					(double)(duration * nr_ticks);
				if (cpu_usage > 0.0) {
					printf("%5.2f %5d %-15s\n",
						cpu_usage, sorted->info->pid, sorted->info->comm);
				}
			}
			sorted = sorted->sorted_usage_next;
		}
		printf("\n");
	}
}


/*
 *  get_cpustats()
 *	scan /proc/cpu_stats and populate a cpu stat hash table with
 *	unique tasks
 */
void get_cpustats(cpu_stat_t *cpu_stats[])	/* hash table to populate */
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
		unsigned long utime;
		unsigned long stime;

		if (!isdigit(entry->d_name[0]))
			continue;

		snprintf(filename, sizeof(filename), "/proc/%s/stat", entry->d_name);
		if ((fp = fopen(filename, "r")) == NULL) 
			continue;
		
		/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */
		fscanf(fp, "%d (%[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
			&pid, comm, &utime, &stime);
		fclose(fp);

		if ((opt_flags & OPT_IGNORE_SELF) && (my_pid == pid))
			continue;

		cpu_stat_add(cpu_stats, pid, comm, utime, stime);
	}

	closedir(dir);
}

/*
 *  show_usage()
 *	show how to use
 */
void show_usage(void)
{
	printf("Usage: %s [-q] [-r csv_file] [-n task_count] [duration] [count]\n", APP_NAME);
	printf("\t-h help\n");
	printf("\t-i ignore %s in the statistics\n", APP_NAME);
	printf("\t-n specifies number of tasks to display\n");
	printf("\t-q run quietly, useful with option -r\n");
	printf("\t-r specifies a comma separated values output file to dump samples into.\n");
	printf("\t-t specifies an task tick count threshold where samples less than this are ignored.\n");
}

int main(int argc, char **argv)
{
	cpu_stat_t **cpu_stats_old, **cpu_stats_new, **tmp;
	int duration = 1;
	int count = 1;
	int n_lines = -1;
	unsigned long whence = 0;
	bool forever = true;
	struct timeval tv1, tv2;

	list_init(&cpu_info_list);
	list_init(&sample_list);

	clock_ticks = sysconf(_SC_CLK_TCK);

	for (;;) {
		int c = getopt(argc, argv, "hin:qr:t:");
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		case 'i':
			opt_flags |= OPT_IGNORE_SELF;
			break;
		case 'n':
			n_lines = atoi(optarg);
			if (n_lines < 1) {
				fprintf(stderr, "-n option must be greater than 0\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			opt_threshold = strtoull(optarg, NULL, 10);
			if (opt_threshold < 1) {
				fprintf(stderr, "-t threshold must be 1 or more.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 'r':
			csv_results = optarg;
			break;
		}
	}

	if (optind < argc) {
		duration = atoi(argv[optind++]);
		if (duration < 1) {
			fprintf(stderr, "Duration must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		forever = false;
		count = atoi(argv[optind++]);
		if (count < 1) {
			fprintf(stderr, "Count must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	opt_threshold *= duration;

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root privileges to read /proc/$pid/stat\n",
			APP_NAME);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, &handle_sigint);

	cpu_stats_old = calloc(TABLE_SIZE, sizeof(cpu_stat_t*));
	cpu_stats_new = calloc(TABLE_SIZE, sizeof(cpu_stat_t*));

	gettimeofday(&tv1, NULL);
	get_cpustats(cpu_stats_old);

	while (!stop_cpustat && (forever || count--)) {
		suseconds_t usec;

		gettimeofday(&tv2, NULL);
		usec = ((tv1.tv_sec + whence + duration - tv2.tv_sec) * 1000000) +
		       (tv1.tv_usec - tv2.tv_usec);
		tv2.tv_sec = usec / 1000000;
		tv2.tv_usec = usec % 1000000;
		
		select(0, NULL, NULL, NULL, &tv2);
		
		get_cpustats(cpu_stats_new);
		cpu_stat_diff(duration, n_lines, whence,
			cpu_stats_old, cpu_stats_new);
		cpu_stat_free_contents(cpu_stats_old);

		tmp             = cpu_stats_old;
		cpu_stats_old = cpu_stats_new;
		cpu_stats_new = tmp;

		whence += duration;
	}

	samples_dump(csv_results, duration);

	cpu_stat_free_contents(cpu_stats_old);
	cpu_stat_free_contents(cpu_stats_new);
	free(cpu_stats_old);
	free(cpu_stats_new);
	samples_free();
	cpu_info_list_free();

	exit(EXIT_SUCCESS);
}
