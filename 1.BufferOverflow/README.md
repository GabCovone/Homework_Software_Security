# 1. Buffer Overflow

In questa challenge si tenta di sfruttare una vulnerabilità di tipo Buffer Overflow al fine di iniettare uno shellcode all'interno dell'applicativo vittima.

L'applicativo da attaccare è `wisdom-alt.c`. Questa applicazione si presenta in questo modo 

## 1. Challenge 

L'obiettivo è di sfruttare l'input che viene raccolto in ingresso per poter iniettare lo shellcode.

Il menu principale è possibile aggirarlo inserendo all'interno del payload che andremo a definire l'opzione insieme a un riempitivo. Il riempitivo è definito per via della funzione `read()` che occupa 1024 caratteri

`$ python3 -c 'import sys; sys.stdout.write("2\n"+ "A"*1022)' > cyclic`

Il passaggio principale è di definire una sequenza ciclica di De Bruijn, al fine di trovare lo stack pointer. Questo ci permetterà di ottenere il giusto offset.

Nel nostro caso, scegliamo una sequenza ciclica di 8 caratteri per 1200 caratteri totali

`cyclic -n 8 1200 >> cyclic`

> immagine wisdom_pwnd

Dopo esserci accertati che l'attacco ha avuto successo, tramite `gdb` analizziamo il punto preciso in cui il programma è fuoriuscito dallo stack pointer, in modo da definire lo spazio per il nostro shellcode

> immagine stack_gdb

nel nostro caso la sequenza da attaccare è la `ctaaaaaa`. usiamo cyclic per scovare dove è collocata la sequenza ciclica

> immagine cyclic -n 8 -l ctaaaaaa

da qui, possiamo creare il nostro script per generare l'attacco

> script 

infine, lo eseguiamo e avviamo una sessione servier in un altro terminale

> SuccessCh1