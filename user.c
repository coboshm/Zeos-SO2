#include <libc.h>

char buff[24];

int pid;

void feina() {
    while(1){    
    write(1,"olaaaaaaaa",10);
    }
    exit();
}

int __attribute__ ((__section__(".text.main")))
  main(void)
{
    /* Next line, tries to move value 0 to CR3 register. This register is a privileged one, and so it will raise an exception */
     /* __asm__ __volatile__ ("mov %0, %%cr3"::"r" (0) ); */   
    char buffer[10];    
    int i = 0;
    long num = 0;
    void* start = sbrk(0);
    while(sbrk(4096)>0) {
        i++;
        num += 4096;
    }
    write(1, "\n", 1);
    write(1,"i: ",3);
    itoa(i, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    write(1,"num: ",5);
    itoa(num, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    write(1,"start0: ",8);
    itoa((int)start, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    start = sbrk(-num);
    write(1,"start1: ",8);
    itoa((int)start, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    i = 0;
    num = 0;
    while(sbrk(4096)>0) {
        i++;
        num += 4096;
    }
    write(1,"i: ",3);
    itoa(i, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);
    write(1,"num: ",5);
    itoa(num, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    start = sbrk(-num);
    write(1,"start1: ",8);
    itoa((int)start, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    i = 0;
    num = 0;
    while(sbrk(4096)>0) {
        i++;
        num += 4096;
    }
    write(1,"i: ",3);
    itoa(i, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);
    write(1,"num: ",5);
    itoa(num, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    start = sbrk(-num);
    write(1,"start1: ",8);
    itoa((int)start, buffer);
    write(1, buffer, strlen(buffer));
    write(1, "\n", 1);

    runjp();

    //char pila[4096];
    //clone(feina,&pila[4096]);
    while(1) {
            //write(1,"escriu algu:",12);
            //read(0,buffer,4);
            //write(1,buffer,4);	      
            //char buffer[10];
	      //itoa(getpid(), buffer);
	      //write(1, buffer, 10);
    }
}
