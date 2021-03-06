/*
 * sched.h - Estructures i macros pel tractament de processos
 */

#ifndef __SCHED_H__
#define __SCHED_H__

#include <list.h>
#include <types.h>
#include <mm_address.h>
#include <stats.h>

#define NR_TASKS      10
#define KERNEL_STACK_SIZE	1024
#define QUANTUM_DEFECTE 20
#define KEYBOARDBUFFER_SIZE 512

enum state_t { ST_RUN, ST_READY, ST_BLOCKED, ST_ZOMBIE };

struct infKey {
    char *buffer;
    int toread;
};

struct task_struct {
  int PID;			/* Process ID */
  page_table_entry * dir_pages_baseAddr;
  struct list_head list;
  void * pointer;
  unsigned int quantum;
  struct stats estats;
  enum state_t estat;
  int info_semf;
  struct infKey info_key;
  void * inici_heap;
  int bytesHeap;
  int numPagesHeap;
};

union task_union {
  struct task_struct task;
  unsigned long stack[KERNEL_STACK_SIZE];    /* pila de sistema, per procés */
};

struct semaphore {
    int cont;
    struct list_head tasks;
    struct task_struct *owner;
};

extern union task_union task[NR_TASKS]; /* Vector de tasques */
extern struct task_struct *idle_task;


#define KERNEL_ESP(t)       	(DWord) &(t)->stack[KERNEL_STACK_SIZE]

#define INITIAL_ESP       	KERNEL_ESP(&task[1])

#define MAX_NUM_SEMAPHORES 20

/* Inicialitza les dades del proces inicial */
void init_task1(void);

void init_idle(void);

void init_sched(void);

struct task_struct * current();

void task_switch(union task_union*t);

struct task_struct *list_head_to_task_struct(struct list_head *l);

page_table_entry * get_PT (struct task_struct *t) ;

page_table_entry * get_DIR (struct task_struct *t) ;

/* Headers for the scheduling policy */
void sched_next_rr();
void update_current_state_rr(struct list_head *dest);
int needs_sched_rr();
void update_sched_data_rr();

int get_quantum (struct task_struct *t);
void set_quantum (struct task_struct *t, int new_quantum);


#endif  /* __SCHED_H__ */
