#ifndef _SYSCALL_H
#define _SYSCALL_H

#ifdef __sparc_v8__

typedef int (*syscall_t)(int,int,int,int,int,int*);

struct stat;

void sys_exit(int);

int sys_nbputch(int ch);
int sys_nbgetch();
extern int sys_write(int,int,int,int,int,int*);
extern int sys_frontend(int,int,int,int,int,int*);

static inline int __write(int fd, const char* ptr, int len)
{
  return sys_write(fd,(int)ptr,len,0,0,0);
}

#define TSC_HZ 1000000

#endif

#define RAMP_SYSCALL_exit		1
#define RAMP_SYSCALL_read		3
#define RAMP_SYSCALL_write		4
#define RAMP_SYSCALL_open		5
#define RAMP_SYSCALL_close		6
#define RAMP_SYSCALL_link		9
#define RAMP_SYSCALL_unlink		10
#define RAMP_SYSCALL_chdir		12
#define RAMP_SYSCALL_chmod		15
#define RAMP_SYSCALL_chown		16
#define RAMP_SYSCALL_brk		17
#define RAMP_SYSCALL_stat		18
#define RAMP_SYSCALL_lseek		19
#define RAMP_SYSCALL_fstat		28
#define RAMP_SYSCALL_utime		30
#define RAMP_SYSCALL_access		33
#define RAMP_SYSCALL_dup		41
#define RAMP_SYSCALL_umask		60
#define RAMP_SYSCALL_fcntl		62
#define RAMP_SYSCALL_kdup		87
#define RAMP_SYSCALL_lstat		88
#define RAMP_SYSCALL_tcgetattr		89
#define RAMP_SYSCALL_tcsetattr		90
#define RAMP_SYSCALL_closedir		91
#define RAMP_SYSCALL_rewinddir		92
#define RAMP_SYSCALL_readdir		93
#define RAMP_SYSCALL_opendir		94
#define RAMP_SYSCALL_dup2		95
#define RAMP_SYSCALL_proc_free		96
#define RAMP_SYSCALL_proc_init		97
#define RAMP_SYSCALL_time		98
#define RAMP_SYSCALL_pread		173
#define RAMP_SYSCALL_pwrite		174
#define RAMP_SYSCALL_getcwd		229

#define RAMP_MAXPATH        1024

#endif

