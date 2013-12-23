GETPID
test getpid: - 0 

FORK 
fork father result: getpid/exit 1 
fork child result: getpid/exit 2 
fork inherit quantum: getpid/exit  3  
fork father and children do not share quantum: getpid/exit 4
fork reset stats: getstats/gepid/exit 5 
fork out of range detection:exit 6
fork data structures recycling after exit: exit 7
fork data copy: inherit and do not share with father: getpid/exit 8 
fork data copy: inherit and do not share with brothers: getpid/exit 9
fork process hierarchy creation: getpid/exit  10
TEST PHYSICAL MEMORY INITIALIZATION P0: exit 11

EXIT
exit(regular process): fork 12
exit(free data frames): fork 13

ROUND ROBIN
ROUND ROBIN:  fork/get_stats 14
FULL QUANTUM AFTER CTX SWITCH: fork/exit/getpid/get_stats 15

GET_STATS 
GET_STATS(pid parameter is negative): - 16
GET_STATS(pid parameter does not exist): - 17
GET_STATS(address parameter is NULL): - 18
GET_STATS(address parameter in kernel address space): - 19
GET_STATS(address parameter outside user address space): - 20
GET_STATS(pid is current process): getpid 21
GET_STATS(process is ready): getpid/fork 22
GET_STATS(process is dead): fork/exit 23 
GET_STATS(process is blocked): fork/exit 24
GET_STATS INCREASING TICKS FOR BLOCKED PROCESSES: fork/exit 25
GET_STATS INCREASING TICKS FOR RUNNING PROCESSES: getpid 26
