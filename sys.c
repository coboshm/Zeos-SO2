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
        actualitzar_usuari_sistema(current());
	actualitzar_sistema_usuari(current());
	return -38; /*ENOSYS*/
}

int sys_getpid()
{
        actualitzar_usuari_sistema(current());
	actualitzar_sistema_usuari(current());
	return current()->PID;
}


int ret_from_fork() {
  return 0;
}

int sys_fork()
{
  
  actualitzar_usuari_sistema(current());
  int new_frames[NUM_PAG_DATA];
  int pag, PID, error;

  if (list_empty(&freequeue)){
 	actualitzar_sistema_usuari(current());
	return -1;
  }  
 //Reservem frames en cas de que no nhi hagui prou els llibrem i retornem error 
  for (pag=0;pag<NUM_PAG_DATA;pag++){
    new_frames[pag] = alloc_frame();
    if (new_frames[pag] < 0) {
      char buffer[10];
      itoa(pag, buffer);
      printk("HA petat: ");
      printk(buffer);
      printk(" esperats: ");
      itoa(NUM_PAG_DATA, buffer);
	printk(buffer);
      printk("\n");
      for (error = pag - 1; error >= 0; error--) {
        free_frame(new_frames[error]);
	printk(" 1 ");
      }
      printk("\n");
      actualitzar_sistema_usuari(current());
      return -ENOMEM;   
    }
  }
  
  //Agafem un PCB lliure i el del pare 
  struct list_head * lh = list_first(&freequeue);
  union task_union *tsku_fill = (union task_union*)list_head_to_task_struct(lh);
  union task_union *tsku_current = (union task_union*)current();    
  list_del(lh);

  //Actualitzem PID
  copy_data(tsku_current,tsku_fill,KERNEL_STACK_SIZE*4);
  allocate_DIR(&tsku_fill->task);

  page_table_entry* taulaP_fill = get_PT(&tsku_fill->task);
  page_table_entry* taulaP_current = get_PT(&tsku_current->task);

  for (pag=0;pag<NUM_PAG_KERNEL + NUM_PAG_CODE;pag++){
    int frame = get_frame(taulaP_current, pag);
    set_ss_pag(taulaP_fill, pag, frame);
  }
  
  int end = NUM_PAG_KERNEL + NUM_PAG_CODE + NUM_PAG_DATA + 1;
  for (pag=0;pag<NUM_PAG_DATA;pag++){
    set_ss_pag(taulaP_fill, NUM_PAG_KERNEL + NUM_PAG_CODE + pag, new_frames[pag]);
    set_ss_pag(taulaP_current, end + pag, new_frames[pag]);
    copy_data((void*)((NUM_PAG_KERNEL + NUM_PAG_CODE + pag)*PAGE_SIZE), (void*)((end + pag)*PAGE_SIZE), PAGE_SIZE);
    del_ss_pag(taulaP_current, end + pag);
  }
  
  set_cr3(get_DIR(&tsku_current->task));

  tsku_fill->stack[KERNEL_STACK_SIZE-18] = &ret_from_fork;
  tsku_fill->stack[KERNEL_STACK_SIZE-19] = 0;
  tsku_fill->task.pointer = &tsku_fill->stack[KERNEL_STACK_SIZE-19];

  
   
  PID = nextFreePID;
  nextFreePID++;
  tsku_fill->task.PID = PID;

  tsku_fill->task.estats.user_ticks = 0;
  tsku_fill->task.estats.system_ticks = 0;
  tsku_fill->task.estats.blocked_ticks = 0;
  tsku_fill->task.estats.ready_ticks = 0;
  tsku_fill->task.estats.elapsed_total_ticks = get_ticks();
  tsku_fill->task.estats.total_trans = 0;
  tsku_fill->task.estats.remaining_ticks = QUANTUM_DEFECTE;
	
  list_add_tail(&tsku_fill->task.list, &readyqueue);
  actualitzar_sistema_usuari(current());
  return PID;

}


void sys_exit()
{  
  actualitzar_usuari_sistema(current());

  struct task_struct * tsk = current();
  free_user_pages(&tsk);
  update_current_state_rr(&freequeue);
  sched_next_rr();

  actualitzar_sistema_usuari(current());
}



int sys_get_stats(int pid,struct stats *st) {
  actualitzar_usuari_sistema(current());
  struct task_struct *tsk;
  if (current()->PID == pid) {
        //aqui fem copy y return
    copy_to_user(&current()->estats,st,sizeof(struct stats));
    actualitzar_sistema_usuari(current());
    return 0;	
  }
  else {
    struct list_head * lh;
    list_for_each(lh, &readyqueue) {
      struct task_struct * tsk = list_head_to_task_struct(lh);
      if (tsk->PID == pid) {
        //aqui fem copy y return
        copy_to_user(&tsk->estats,st,sizeof(struct stats));
  	actualitzar_sistema_usuari(current());
        return 0;      
      }
    }
  }
  actualitzar_sistema_usuari(current());
  return -1;
}


int sys_write(int fd, char * buffer, int size) {
/*    fd: file descriptor. In this delivery it must always be 1.
      buffer: pointer to the bytes.
      size: number of bytes.
      return ’ Negative number in case of error (specifying the kind of error) and
      the number of bytes written if OK.*/
      // Checks the parametres
      actualitzar_usuari_sistema(current());
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
      else {
	 actualitzar_sistema_usuari(current());
	 return num;
      }
}


int sys_gettime() {
      actualitzar_usuari_sistema(current());
      actualitzar_sistema_usuari(current());
      return zeos_ticks;
}

void actualitzar_usuari_sistema(struct task_struct* tsk){
  tsk->estats.user_ticks += get_ticks() - tsk->estats.elapsed_total_ticks;
  tsk->estats.elapsed_total_ticks = get_ticks();
}

void actualitzar_sistema_usuari(struct task_struct* tsk){
  tsk->estats.system_ticks += get_ticks() - tsk->estats.elapsed_total_ticks;
  tsk->estats.elapsed_total_ticks = get_ticks();
}
