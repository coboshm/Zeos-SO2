GETPID
test getpid: -

FORK 
fork father result: getpid/exit
fork child result: getpid/exit
fork inherit quantum: getpid/exit  
fork father and children do not share quantum: getpid/exit
fork reset stats: getstats/gepid/exit
fork out of range detection:exit
fork data structures recycling after exit: exit
fork data copy: inherit and do not share with father: getpid/exit
fork data copy: inherit and do not share with brothers: getpid/exit
fork process hierarchy creation: getpid/exit
TEST PHYSICAL MEMORY INITIALIZATION P0: exit

EXIT
exit(regular process): fork
exit(free data frames): fork

ROUND ROBIN
ROUND ROBIN:  fork/get_stats
FULL QUANTUM AFTER CTX SWITCH: fork/exit/getpid/get_stats

GET_STATS
GET_STATS(pid parameter is negative): -
GET_STATS(pid parameter does not exist): -
GET_STATS(address parameter is NULL): -
GET_STATS(address parameter in kernel address space): -
GET_STATS(address parameter outside user address space): -
GET_STATS(pid is current process): getpid
GET_STATS(process is ready): getpid/fork
GET_STATS(process is dead): fork/exit
GET_STATS(process is blocked): fork/exit
GET_STATS INCREASING TICKS FOR BLOCKED PROCESSES: fork/exit
GET_STATS INCREASING TICKS FOR RUNNING PROCESSES: getpid
