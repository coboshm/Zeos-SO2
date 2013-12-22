/*
 * sched.c - initializes struct for task 0 anda task 1
 */

#include <sched.h>
#include <mm.h>
#include <io.h>
#include <capsaleres.h>

struct task_struct * idle_task;
int nextFreePID = 2;

union task_union task[NR_TASKS]
  __attribute__((__section__(".data.task")));


struct task_struct *list_head_to_task_struct(struct list_head *l)
{
  return list_entry( l, struct task_struct, list);
}

extern struct list_head blocked;


/* get_DIR - Returns the Page Directory address for task 't' */
page_table_entry * get_DIR (struct task_struct *t) 
{
	return t->dir_pages_baseAddr;
}

/* get_PT - Returns the Page Table address for task 't' */
page_table_entry * get_PT (struct task_struct *t) 
{
	return (page_table_entry *)(((unsigned int)(t->dir_pages_baseAddr->bits.pbase_addr))<<12);
}


int allocate_DIR(struct task_struct *t) 
{
	int pos;

	pos = ((int)t-(int)task)/sizeof(union task_union);

	t->dir_pages_baseAddr = (page_table_entry*) &dir_pages[pos]; 

	return 1;
}

void cpu_idle(void)
{
	__asm__ __volatile__("sti": : :"memory");
	while(1)
	{
	;
	}
}

void init_idle (void)
{
	struct list_head * lh = list_first(&freequeue);
	struct task_struct * tsk = list_head_to_task_struct(lh);
	list_del(lh);
    tsk->PID = 0;
	idle_task = tsk;
	union task_union * tsku = (union task_union *)idle_task;
	tsku->stack[KERNEL_STACK_SIZE-1] = &cpu_idle;
	tsku->stack[KERNEL_STACK_SIZE-2] = 0;
	idle_task->pointer = &tsku->stack[KERNEL_STACK_SIZE-2];
}

void init_task1(void)
{
	struct list_head * lh = list_first(&freequeue);
	struct task_struct * tsk = list_head_to_task_struct(lh);
	list_del(lh);
    tsk->PID = 1;
	set_user_pages(tsk);
	union task_union * tsku = (union task_union *)tsk;
	tss.esp0 = &tsku->stack[KERNEL_STACK_SIZE];
	set_cr3(tsk->dir_pages_baseAddr);
}


void init_sched(){
    int i;
    INIT_LIST_HEAD(&readyqueue);
    INIT_LIST_HEAD(&freequeue);
    for (i = 0; i < NR_TASKS; ++i) {
        list_add(&(task[i].task.list), &freequeue);
    }
}

void inner_task_switch(union task_union*t){
	void * old = current()->pointer;
	void * new = (t->task).pointer;
	__asm__ __volatile__(
		"movl %%ebp,%0;"
		"movl %1,%%esp;"
		"popl %%ebp;"
		"ret;"
	:
	: "g" (old), "g" (new)
      );
}

void task_switch(union task_union*t){
       tss.esp0 = &t->stack[KERNEL_STACK_SIZE];
       set_cr3(t->task.dir_pages_baseAddr);
       __asm__ __volatile__(
		"pushl %esi;"
		"pushl %edi;"
		"pushl %ebx;"
      );
      inner_task_switch(t);
      __asm__ __volatile__(
		"popl %esi;"
		"popl %edi;"
		"popl %ebx;"
      );
}

struct task_struct* current()
{
  int ret_value;
  
  __asm__ __volatile__(
  	"movl %%esp, %0"
	: "=g" (ret_value)
  );
  return (struct task_struct*)(ret_value&0xfffff000);
}

