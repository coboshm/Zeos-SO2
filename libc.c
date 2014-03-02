/*
 * libc.c 
 */

#include <libc.h>
#include <types.h>
#include <capsaleres.h>
#include <errno.h>

int errno;

void perror(void) {
  if (errno < MIN_ERRNO_VALUE || errno > MAX_ERRNO_VALUE) errno = 1;
  write(1,"ERROR DESCRIPTION: ",19);
  write(1, errors[errno - 1], strlen(errors[errno - 1]));
  write(1,"\n",1);
}


void itoa(int a, char *b)
{
  int i, i1;
  char c;
  
  if (a==0) { b[0]='0'; b[1]=0; return ;}
  
  i=0;
  while (a>0)
  {
    b[i]=(a%10)+'0';
    a=a/10;
    i++;
  }
  
  for (i1=0; i1<i/2; i1++)
  {
    c=b[i1];
    b[i1]=b[i-i1-1];
    b[i-i1-1]=c;
  }
  b[i]=0;
}

int strlen(char *a)
{
  int i;
  
  i=0;
  
  while (a[i]!=0) i++;
  
  return i;
}


int write(int fd, char *buffer, int size) {
     int ret = -1;
     __asm__ __volatile__ (
          "movl %1, %%ebx;"
	      "movl %2, %%ecx;"
	      "movl %3, %%edx;"
	      "movl $4, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
          : "g" (fd), "g"(buffer), "g" (size)
          : "ax", "bx", "cx", "dx"
    );
    if(ret >= 0) return ret;
    else {
	errno = -ret;
	return -1;
    }
}


int getpid(void) {
    int ret;
	__asm__ volatile(
				"movl $20, %%eax;"
	            "int $0x80;"
	            "movl %%eax, %0;"
				:"=g" (ret)
                :
                : "ax"
	);
	return ret;
}


int fork(void) {
    int ret;
	__asm__ volatile(
				"movl $2, %%eax;"
	      "int $0x80;"
        "movl %%eax, %0;"
				:"=g" (ret)
        :
        : "ax"
	);
	if(ret >= 0) return ret;
    	else {
		errno = -ret;
		return -1;
    	}
}


void exit(void) {
	__asm__ volatile(
				"movl $1, %%eax;"
	      "int $0x80;"
				:
        :
        : "ax"
	);
}

int get_stats(int pid, struct stats *st) {
     int ret = -1;
     __asm__ __volatile__ (
        "movl %1, %%ebx;"
	      "movl %2, %%ecx;"
	      "movl $35, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
        : "g" (pid), "g"(st)
        : "ax", "bx", "cx", "dx"
    );
    if(ret >= 0) return ret;
    else {
        errno = -ret;
	      return -1;
    }
}

long long int gettime() {
	long long int ret = -1;
	__asm__ __volatile__ (
		"movl $10, %%eax;"
		"int $0x80;"
		"movl %%eax, %0;"
		: "=g" (ret)
		:
		: "ax"
	);
	if(ret >= 0) return ret;
	else {
		errno = -ret;
		return -1;
	}	
}


int sem_init (int n_sem, unsigned int value) {
    //n_sem: identifier of the semaphore to be initialized
    //value: initial value of the counter of the semaphore
     int ret = -1;
     __asm__ __volatile__ (
        "movl %1, %%ebx;"
	      "movl %2, %%ecx;"
	      "movl $21, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
        : "g" (n_sem), "g"(value)
        : "ax", "bx", "cx"
    );
    if(ret >= 0) return ret;
    else {
        errno = -ret;
	    return -1;
    }
}


int sem_wait(int n_sem) {
     int ret = -1;
     __asm__ __volatile__ (
          "movl %1, %%ebx;"
	      "movl $22, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
        : "g" (n_sem)
        : "ax", "bx"
    );
    if(ret >= 0) return ret;
    else {
        errno = -ret;
	    return -1;
    }
}

int sem_signal(int n_sem) {
    int ret = -1;
     __asm__ __volatile__ (
          "movl %1, %%ebx;"
	      "movl $23, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
        : "g" (n_sem)
        : "ax", "bx"
    );
    if(ret >= 0) return ret;
    else {
        errno = -ret;
	    return -1;
    }
}

int sem_destroy(int n_sem) {
    int ret = -1;
     __asm__ __volatile__ (
          "movl %1, %%ebx;"
	      "movl $24, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
        : "g" (n_sem)
        : "ax", "bx"
    );
    if(ret >= 0) return ret;
    else {
        errno = -ret;
	    return -1;
    }
}

int clone (void (*function)(void), void *stack) {
    //function: starting address of the function to be executed by the new process
    //stack   : starting address of a memory region to be used as a stack
    //returns: -1 if error or the pid of the new lightweight process ID if OK
    int ret = -1;
     __asm__ __volatile__ (
          "movl %1, %%ebx;"
          "movl %2, %%ecx;"
	      "movl $19, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
        : "g" (function), "g" (stack)
        : "ax", "bx","cx"
    );
    if(ret >= 0) return ret;
    else {
        errno = -ret;
	    return -1;
    }
}

int read(int fd, char *buffer, int count) {
     int ret = -1;
     __asm__ __volatile__ (
          "movl %1, %%ebx;"
	      "movl %2, %%ecx;"
	      "movl %3, %%edx;"
	      "movl $5, %%eax;"
	      "int $0x80;"
	      "movl %%eax, %0;"
	      : "=g" (ret)
          : "g" (fd), "g"(buffer), "g" (count)
          : "ax", "bx", "cx", "dx"
    );
    if(ret >= 0) return ret;
    else {
	errno = -ret;
	return -1;
    }
}

void *sbrk(int increment) {
     int ret = -1;
     __asm__ __volatile__ (
          "movl %1, %%ebx;"
	  "movl $6, %%eax;"
	  "int $0x80;"
	  "movl %%eax, %0;"
	      : "=g" (ret)
        : "g" (increment)
        : "ax", "bx"
    );
    if(ret >= 0) return ret;
    else {
        errno = -ret;
	return -1;
    }
}




