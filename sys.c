/*
 * sys.c - Syscalls implementation
 */
#include <devices.h>

#include <utils.h>

#include <io.h>

#include <mm.h>

#include <capsaleres.h>

#include <mm_address.h>

#include <errno.h>

#include <sched.h>

#define LECTURA 0
#define ESCRIPTURA 1

int check_fd(int fd, int permissions)
{
  if (fd!=1) return -9; /*EBADF*/
  if (permissions!=ESCRIPTURA) return -13; /*EACCES*/
  return 0;
}

int sys_ni_syscall()
{
	return -38; /*ENOSYS*/
}

int sys_getpid()
{
	return current()->PID;
}

int sys_fork()
{
  int error = 0;

  if (list_empty(&freequeue)) return -1;
  struct list_head * lh = list_first(&freequeue);
	struct task_struct * tsk = list_head_to_task_struct(lh);

  struct task_struct * tskc = current();
  int PID = nextFreePID++;
  copy_data(tskc, tsk, KERNEL_STACK_SIZE);
  tsk->PID = PID;
  int retalloc = allocate_DIR(tsk);
  if (retalloc < 0) return retalloc;

  int pag, new_ph_pag;
  for (pag=0;pag<NUM_PAG_KERNEL;pag++){
    int frame = get_frame(tskc->dir_pages_baseAddr, pag);
    set_ss_pag(tsk->dir_pages_baseAddr, pag, frame);
  }

  int end = NUM_PAG_KERNEL + NUM_PAG_CODE + NUM_PAG_DATA + 1;
  for (pag=0;pag<NUM_PAG_CODE && error == 0;pag++){
	  new_ph_pag = alloc_frame();
    if (new_ph_pag < 0) {
      undo();
      error = new_ph_pag;
    }
    set_ss_pag(tsk->dir_pages_baseAddr, NUM_PAG_KERNEL + pag, new_ph_pag);
    set_ss_pag(tskc->dir_pages_baseAddr, end + pag, new_ph_pag);
    copy_data((tskc->dir_pages_baseAddr)[NUM_PAG_KERNEL + pag], (tskc->dir_pages_baseAddr)[end + pag], PAGE_SIZE);
    del_ss_pag(tskc->dir_pages_baseAddr, end + pag);
  }
  
  for (pag=0;pag<NUM_PAG_DATA;pag++){
	  new_ph_pag=alloc_frame();
    if (new_ph_pag < 0) return new_ph_pag;
  }
    
 
	list_del(lh);
// ADD a sa ready

  return PID;
}

void sys_exit()
{  
}


int sys_write(int fd, char * buffer, int size) {
/*    fd: file descriptor. In this delivery it must always be 1.
      buffer: pointer to the bytes.
      size: number of bytes.
      return ’ Negative number in case of error (specifying the kind of error) and
      the number of bytes written if OK.*/
      // Checks the parametres
      int size_original = size;
      int check = check_fd(fd, ESCRIPTURA);
      if(check != 0) return check;
      if (buffer == NULL) return -EFAULT;
      if (size < 0) return -EINVAL;
      
      char buff[4];
      int num = 0;
      while(size >= 4) {
      	check = copy_from_user(buffer, buff, 4);
      	num += sys_write_console(buff, 4);
	buffer += 4;
	size -= 4;
      }
      check = copy_from_user(buffer, buff, size);
      num += sys_write_console(buff, size);
      if (num != size_original) return -ENODEV;
      else return num;
}


int sys_gettime() {
      return zeos_ticks;
}
