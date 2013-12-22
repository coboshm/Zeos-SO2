* Fitxers inclossos:

- README.txt: aquest fitxer d'ajuda
- libauxjp.a: llibreria de sistema addicional per a usar els jocs de proves
- zeosjp.tar.gz: 2n joc de proves


* Instal.lació.
Per tal de poder usar aquests jocs de proves cal que existeixen una serie de funcionalitats extres dins el sistema, aquestes funcionalitats les ofereix la llibreria 'libauxjp.a'. Cal inserir aquesta llibreria dins el sistema i per fer-ho cal:
1) modificar la linia de linkatge del Makefile:

LIBZEOS= -L. -l zeos

per afegir la nova llibreria a la fase de linkatge del sistema:

LIBZEOS= -L. -l zeos -l auxjp

2) Afegir una crida a la rutina 'zeos_init_auxjp()' dins el main del system.c, just abans de saltar a mode usuari, per inicialitzar la lliberia.


* Requisits
Aquesta nova llibreria usa les estructures i funcions que teniu definides dins el vostre sistema per tant és imprescindible que com a mínim tingueu:
- la llista de procesos READY amb nom 'readyqueue'
- funcions per consultar/modificar el quantum (get_quantum, set_quantum)
- politica de planificacio round-robin (update_current_state_rr, sched_next_rr) 

