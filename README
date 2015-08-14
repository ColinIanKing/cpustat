cpustat

cpustat periodically dumps out the current CPU utilisation statistics of
running processes. cpustat has been optimised to have a minimal CPU overhead
and typically uses about 35% of the CPU compared to top. cpustat also includes
some simple statistical analysis options that can help characterise the way
CPUs are being loaded.

cpustat command line options:

    -h help
    -a calculate CPU utilisation based on all the CPU ticks rather than one CPU
    -c get command name from processes comm field (less expensive on CPU)
    -d strip directory basename off command information
    -D show distribution of CPU utilisation stats at end of run
    -g show grand total of CPU utilisation stats at end of run
    -i ignore cpustat in the statistics
    -l show long (full) command information
    -n specifies number of tasks to display
    -q run quietly, useful with option -r
    -r specifies a comma separated values output file to dump samples into.
    -s show short command information
    -S timestamped output
    -t specifies an task tick count threshold where samples less than this
       are ignored.
    -T show total CPU utilisation statistics
    -x show extra stats (load average, avg cpu freq, etc) 


Example Output:

cpustat 5 5 -gxDST
Load Avg 1.71 1.11 0.88, Freq Avg. 2.92 GHz, 4 CPUs online
7248.5 Ctxt/s, 2444.1 IRQ/s, 1658.1 softIRQ/s, 1.2 new tasks/s, 9 running, 0 blocked
  %CPU   %USR   %SYS   PID S  CPU   Time Task  (14:09:46)
 73.25  73.25   0.00 31078 S    2  1.94m stress-ng
 72.06  70.86   1.20 31079 R    1  1.94m stress-ng
 20.36  16.97   3.39 31037 S    0 33.28s /usr/lib/firefox/plugin-container
  8.78   7.98   0.80  7027 S    3 42.70s /usr/lib/thunderbird/thunderbird
  4.99   3.19   1.80  7134 S    3  1.94m /usr/lib/firefox/firefox
  4.79   3.19   1.60   901 S    3  8.06m /usr/bin/X
  3.39   2.99   0.40  2250 S    2  3.99m compiz
  1.60   0.80   0.80  2375 S    2  1.58m /usr/bin/pulseaudio
  1.60   0.00   1.60 31036 S    0  1.12s [kworker/0:2]
  0.40   0.40   0.00  5719 S    2 22.10s /usr/lib/gnome-terminal/gnome-terminal-server
  0.40   0.40   0.00  2177 S    3 21.25s /usr/bin/ibus-daemon
  0.20   0.20   0.00 30774 S    0  1.03s /usr/lib/firefox/plugin-container
  0.20   0.00   0.20   493 S    2  0.25s [jbd2/sda3-8]
  0.20   0.20   0.00  2206 S    3  3.44s /usr/lib/ibus/ibus-ui-gtk3
  0.20   0.00   0.20  6852 S    3  0.24s [kworker/3:1]
  0.20   0.20   0.00  2170 S    1  0.25s upstart-dbus-bridge
  0.20   0.00   0.20  6806 S    2 12.18s [kworker/u16:3]
192.81 180.64  12.18 Total

Load Avg 1.82 1.14 0.90, Freq Avg. 2.92 GHz, 4 CPUs online
6781.6 Ctxt/s, 2210.8 IRQ/s, 1338.8 softIRQ/s, 0.6 new tasks/s, 2 running, 0 blocked
  %CPU   %USR   %SYS   PID S  CPU   Time Task  (14:09:51)
 73.40  73.40   0.00 31079 R    1  2.00m stress-ng
 72.80  71.40   1.40 31078 S    2  2.00m stress-ng
 19.40  17.40   2.00 31037 S    0 34.25s /usr/lib/firefox/plugin-container
 15.00  13.80   1.20  7027 S    3 43.45s /usr/lib/thunderbird/thunderbird
  5.60   3.40   2.20   901 S    3  8.06m /usr/bin/X
  3.60   2.80   0.80  2250 S    2  4.00m compiz
  3.20   2.40   0.80  7134 S    3  1.94m /usr/lib/firefox/firefox
  1.60   1.20   0.40  2375 S    2  1.58m /usr/bin/pulseaudio
  1.00   0.00   1.00 31036 S    0  1.17s [kworker/0:2]
  0.20   0.00   0.20 30774 S    0  1.04s /usr/lib/firefox/plugin-container
  0.20   0.20   0.00  2244 S    2  1.68s /usr/lib/unity-settings-daemon/unity-settings-daemon
  0.20   0.20   0.00  2263 S    2  2.17s /usr/lib/unity/unity-panel-service
  0.20   0.20   0.00   770 S    3  1.85s /usr/bin/dbus-daemon
  0.20   0.20   0.00   722 S    1  1.14s /usr/lib/accountsservice/accounts-daemon
  0.20   0.00   0.20 30780 S    0  2.05s /opt/google/talkplugin/GoogleTalkPlugin
  0.20   0.20   0.00  2292 S    0  0.72s /usr/lib/x86_64-linux-gnu/indicator-messages/indicator-messages-service
  0.20   0.20   0.00  2300 S    0  0.90s /usr/lib/x86_64-linux-gnu/indicator-sound/indicator-sound-service
197.20 187.00  10.20 Total

Load Avg 1.75 1.14 0.90, Freq Avg. 2.90 GHz, 4 CPUs online
3776.4 Ctxt/s, 1477.4 IRQ/s, 789.0 softIRQ/s, 0.2 new tasks/s, 3 running, 0 blocked
  %CPU   %USR   %SYS   PID S  CPU   Time Task  (14:09:56)
 74.80  74.80   0.00 31078 S    2  2.06m stress-ng
 74.20  74.20   0.00 31079 R    1  2.06m stress-ng
 18.80  16.60   2.20 31037 S    0 35.19s /usr/lib/firefox/plugin-container
  5.00   4.40   0.60  7027 S    3 43.70s /usr/lib/thunderbird/thunderbird
  3.00   1.40   1.60   901 S    3  8.07m /usr/bin/X
  2.00   1.60   0.40  2250 S    2  4.00m compiz
  1.40   0.60   0.80  2375 S    2  1.59m /usr/bin/pulseaudio
  0.80   0.80   0.00  7134 S    3  1.94m /usr/lib/firefox/firefox
  0.20   0.20   0.00 30774 S    0  1.05s /usr/lib/firefox/plugin-container
  0.20   0.20   0.00 30780 S    0  2.06s /opt/google/talkplugin/GoogleTalkPlugin
  0.20   0.00   0.20 31036 S    0  1.18s [kworker/0:2]
  0.20   0.00   0.20 30763 S    1  3.39s [kworker/u16:1]
  0.20   0.00   0.20 31116 R    2  0.01s ./cpustat
181.00 174.80   6.20 Total

Load Avg 2.01 1.21 0.92, Freq Avg. 2.93 GHz, 4 CPUs online
3227.0 Ctxt/s, 1315.4 IRQ/s, 723.0 softIRQ/s, 0.2 new tasks/s, 2 running, 0 blocked
  %CPU   %USR   %SYS   PID S  CPU   Time Task  (14:10:01)
 75.80  75.80   0.00 31078 S    2  2.13m stress-ng
 74.20  74.00   0.20 31079 R    1  2.12m stress-ng
 19.60  18.80   0.80 31037 S    0 36.17s /usr/lib/firefox/plugin-container
  2.40   1.60   0.80   901 S    3  8.07m /usr/bin/X
  2.20   2.00   0.20  2250 S    2  4.00m compiz
  1.60   1.60   0.00  7027 S    3 43.78s /usr/lib/thunderbird/thunderbird
  1.40   1.00   0.40  2375 S    2  1.59m /usr/bin/pulseaudio
  0.60   0.60   0.00  7134 S    3  1.94m /usr/lib/firefox/firefox
  0.20   0.00   0.20  2263 S    2  2.18s /usr/lib/unity/unity-panel-service
  0.20   0.00   0.20     3 S    0  0.59s [ksoftirqd/0]
178.20 175.40   2.80 Total

Load Avg 1.93 1.20 0.92, Freq Avg. 2.90 GHz, 4 CPUs online
4781.8 Ctxt/s, 1809.4 IRQ/s, 871.8 softIRQ/s, 0.2 new tasks/s, 3 running, 0 blocked
  %CPU   %USR   %SYS   PID S  CPU   Time Task  (14:10:06)
 74.00  73.80   0.20 31078 S    2  2.19m stress-ng
 72.80  72.60   0.20 31079 R    1  2.18m stress-ng
 18.40  17.00   1.40 31037 S    0 37.09s /usr/lib/firefox/plugin-container
  6.00   5.60   0.40  7027 S    3 44.08s /usr/lib/thunderbird/thunderbird
  5.60   2.80   2.80   901 S    3  8.07m /usr/bin/X
  5.00   4.00   1.00  2250 S    2  4.00m compiz
  1.60   1.40   0.20  7134 S    3  1.94m /usr/lib/firefox/firefox
  1.40   0.60   0.80  2375 S    2  1.59m /usr/bin/pulseaudio
  0.60   0.60   0.00  5719 S    2 22.13s /usr/lib/gnome-terminal/gnome-terminal-server
  0.40   0.40   0.00  2430 S    1  2.96s nautilus
  0.20   0.20   0.00  2263 S    2  2.19s /usr/lib/unity/unity-panel-service
  0.20   0.00   0.20     7 S    0  2.33s [rcu_sched]
  0.20   0.00   0.20 30780 S    0  2.07s /opt/google/talkplugin/GoogleTalkPlugin
  0.20   0.00   0.20 31036 S    0  1.19s [kworker/0:2]
186.60 179.00   7.60 Total

Grand Total (from 5 samples, 25.0 seconds):
  %CPU   %USR   %SYS   PID S  CPU   Time Task  (14:10:06)
 74.13  73.81   0.32 31078 S    2  2.19m stress-ng
 73.33  73.01   0.32 31079 R    1  2.18m stress-ng
 19.31  17.35   1.96 31037 S    0 37.09s /usr/lib/firefox/plugin-container
  7.28   6.68   0.60  7027 S    3 44.08s /usr/lib/thunderbird/thunderbird
  4.28   2.48   1.80   901 S    3  8.07m /usr/bin/X
  3.24   2.68   0.56  2250 S    2  4.00m compiz
  2.24   1.68   0.56  7134 S    3  1.94m /usr/lib/firefox/firefox
  1.48   0.84   0.64  2375 S    2  1.59m /usr/bin/pulseaudio
  0.60   0.00   0.60 31036 S    0  1.19s [kworker/0:2]
  0.20   0.20   0.00  5719 S    2 22.13s /usr/lib/gnome-terminal/gnome-terminal-server
  0.12   0.04   0.08 30780 S    0  2.07s /opt/google/talkplugin/GoogleTalkPlugin
  0.12   0.08   0.04 30774 S    0  1.05s /usr/lib/firefox/plugin-container
  0.12   0.08   0.04  2263 S    2  2.19s /usr/lib/unity/unity-panel-service
  0.08   0.08   0.00  2430 S    1  2.96s nautilus
  0.08   0.08   0.00  2177 S    3 21.25s /usr/bin/ibus-daemon
  0.04   0.00   0.04 31116 R    2  0.01s ./cpustat
  0.04   0.00   0.04 30763 S    1  3.39s [kworker/u16:1]
  0.04   0.00   0.04  6852 S    3  0.24s [kworker/3:1]
  0.04   0.00   0.04  6806 S    2 12.18s [kworker/u16:3]
  0.04   0.04   0.00  2300 S    0  0.90s /usr/lib/x86_64-linux-gnu/indicator-sound/indicator-sound-service
  0.04   0.04   0.00  2292 S    0  0.72s /usr/lib/x86_64-linux-gnu/indicator-messages/indicator-messages-service
  0.04   0.04   0.00  2244 S    2  1.68s /usr/lib/unity-settings-daemon/unity-settings-daemon
  0.04   0.04   0.00  2206 S    3  3.44s /usr/lib/ibus/ibus-ui-gtk3
  0.04   0.04   0.00  2170 S    1  0.25s upstart-dbus-bridge
  0.04   0.04   0.00   770 S    3  1.85s /usr/bin/dbus-daemon
  0.04   0.04   0.00   722 S    1  1.14s /usr/lib/accountsservice/accounts-daemon
  0.04   0.00   0.04   493 S    2  0.25s [jbd2/sda3-8]
  0.04   0.00   0.04     7 S    0  2.33s [rcu_sched]
  0.04   0.00   0.04     3 S    0  0.59s [ksoftirqd/0]
187.17 179.37   7.80 Total

Distribution of CPU utilisation (per Task):
% CPU Utilisation   Count   (%)
  0.00 -   3.79      1086  97.84
  3.79 -   7.58         7   0.63
  7.58 -  11.37         1   0.09
 11.37 -  15.16         1   0.09
 15.16 -  18.95         2   0.18
 18.95 -  22.74         3   0.27
 22.74 -  26.53         0   0.00
 26.53 -  30.32         0   0.00
 30.32 -  34.11         0   0.00
 34.11 -  37.90         0   0.00
 37.90 -  41.69         0   0.00
 41.69 -  45.48         0   0.00
 45.48 -  49.27         0   0.00
 49.27 -  53.06         0   0.00
 53.06 -  56.85         0   0.00
 56.85 -  60.64         0   0.00
 60.64 -  64.43         0   0.00
 64.43 -  68.22         0   0.00
 68.22 -  72.01         3   0.27
 72.01 -  75.80         7   0.63

Distribution of CPU utilisation (per CPU):
 CPU#   USR%   SYS%
    0  17.55   2.76
    1  73.17   0.36
    2  77.65   1.68
    3  11.00   3.00

(C) Colin King,  colin.king@canonical.com
Fri Aug 14 2015
