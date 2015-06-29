#ifndef ROS_KERN_MONITOR_H
#define ROS_KERN_MONITOR_H
#ifndef ROS_KERNEL
# error "This is a ROS kernel header; user programs should not #include it"
#endif

// Activate the kernel monitor,
// optionally providing a trap frame indicating the current state
// (NULL if none).
void monitor(trapframe_t *tf);

// Functions implementing monitor commands.
int mon_help(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_kerninfo(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_backtrace(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_ps(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_reboot(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_showmapping(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_setmapperm(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_cpuinfo(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_nanwan(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_bin_ls(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_bin_run(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_manager(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_procinfo(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_exit(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_kfunc(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_notify(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_measure(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_trace(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_monitor(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_fs(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_bb(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_alarm(int argc, char *NTS *NT COUNT(argc) argv, trapframe_t *tf);
int mon_bcq(int argc, char **argv, struct trapframe *tf);

#endif	// !ROS_KERN_MONITOR_H
