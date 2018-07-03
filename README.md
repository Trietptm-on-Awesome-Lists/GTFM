<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <link rel="stylesheet" href="https://stackedit.io/style.css" />
</head>
<body class="stackedit">
  <div class="stackedit__html"><h1 id="manual">Exploiting, reversing y ++</h1>
  <pre><code>❯ ./exploiting_reversing

	                      .".
                         /  |
                        /  /
                       / ,"
           .-------.--- /
          ".____.-/ o. o\
                 (    Y  )
                  )     /
                 /     (
                /       Y
            .-"         |
           /  _     \    \
          /    `. ". ) /' )
         Y       )( / /(,/
        ,|      /     )
       (_|     /     /
          \_  (__   (__        
            "-._,)--._,)
</code></pre>
<p>Escrito por Alvaro M. aka <code>@naivenom</code>.</p>
<h2 id="indice">Indice</h2>
<h4 id="indice-exploiting">[Exploiting]</h4>
<p>1. Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros + float value + shellcode (I)</p>
<h2 id="introduccion">Introduccion</h2>
<p>Recomiendo que se tome este manual como una referencia y no una explicacion detallada de los retos que he ido realizando a lo largo del 2018/2019. 
Realmente cada reto esta dividido en seis apartados con lo mas resañable e interesante a la hora de usar el black field manual como una referencia y consulta
a la hora de estar resolviendo un reto y ver la tecnica usada, los comandos usados, un breve resumen de un informe mas detallado y el codigo del exploit.</p>
<h2 id="precision-100"> #1# Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros + float value + shellcode</h2>
<h4>[Resumen]:</h4><p>Tenemos que explotar un Buffer Overflow protegido con un stack canary float value</p>
<h4>[Tecnica]:</h4><p>Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros + float value + shellcode</p>
<h4>[Informe]:</h4><p>Comenzamos analizando estaticamente el codigo desensamblado del binario. La funcion mas resañable donde se encuentra la vulnerabilidad es en el <code>main()</code>. 
En esta funcion una vez es llamada y configurar el stack en el prologo ejecuta una instruccion realizando floating load <code>fld qword [0x8048690]</code>.
Seguidamente carga el float value en el stack <code>fstp qword [esp + 0x98]</code>. Luego analizando el desensamblado del binario realiza una serie de llamadas a 
<code>printf()</code>, <code>scanf()</code> y probablemente tengamos un Buffer Overflow (BoF de ahora en adelante) despues de la funcion <code>scanf()</code> porque no controlora o checkeara cuantos caracteres o "junk" le enviemos en nuestro payload. 
Finalmente en el mismo bloque antes de llegar a un salto condicional y despues de ejecutar <code>scanf()</code> ejecuta la misma instruccion <code>fld qword [esp + 0x98]</code> realizando floating load donde previamente se escribio en el Stack y seguidamente ejecuta <code>fld qword [0x8048690]</code> siendo el original float value del calculo realizado en la FPU. Despues de estas dos instrucciones tan relevantes realiza <code>fucompi st(1)</code> comparando ambos valores. Por tanto esta comprobacion que se realiza cuando se ejecuta despues del prologo y antes del salto condicional es una especie de Stack Canary</p>
<pre><code>❯ Ejemplo_                                                                         
Buffer:            AAAAAAAAAAAAAAAAAAAAAAAAAA + 0.245454 + EIP
Smashing Float:    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA + MEMORY ADDRESS que queremos controlar
                                                          
FUCOMPI:           AAAAAAAA != 0.245454   Security Detected!

Bypass:            AAAAAAAAAAAAAAAAAAAAAAAAAA + 0.245454 + MEMORY ADDRESS
</code></pre>
<h4>[Comandos]:</h4><pre><code>❯ r2 -d precision                                                                            
[0x0804851d]> db 0x080485a3 #Colocamos un bp justo en la instruccion fucompi
[0x0804851d]> dc #Ejecutamos hasta el bp
Buff: 0xffa3d9e8
AAAAAAAAAAAAAAAAAAAAAAAA
hit breakpoint at: 80485a3

[0x0804851d]> vpp #Entramos en visual mode
[0x080485a3 170 /home/naivenom/pwn/precision]> ?0;f tmp;s.. @ eip                                                                         
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF                                                                     
0xffa3d9d0  8286 0408 e8d9 a3ff 0200 0000 0000 0000  ................                                                                     
0xffa3d9e0  9c1a f3f7 0100 0000 4141 4141 4141 4141  ........AAAAAAAA                                                                     
0xffa3d9f0  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA                                                                     
0xffa3da00  0000 0000 0000 c300 0000 0000 0010 f3f7  ................                                                                     
 eax 0x00000001      ebx 0x00000000      ecx 0x00000001      edx 0xf7ed689c                                                               
 esi 0xf7ed5000      edi 0x00000000      esp 0xffa3d9d0      ebp 0xffa3da78                                                               
 eip 0x080485a3      eflags 1ZI         oeax 0xffffffff                                                                                   
            ;-- eip:                                                                                                                      
|           0x080485a3 b    dfe9           fucompi st(1)                                                                                  
|           0x080485a5      ddd8           fstp st(0)

[0x080485a3]> px@esp+0x98
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffa3da68  a531 5a47 5515 5040 0050 edf7 0050 edf7  .1ZGU.P@.P...P..

</code></pre>
<pre><code>❯ gdb -q precision

</code></pre>
<h4>[Exploit]:</h4><p></p>
<h4>[URL Reto]:</h4><p>--Precision100 CSAW CTF 2015--, https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/pwn/precision-100/precision_a8f6f0590c177948fe06c76a1831e650</p>

</div>
</body>

</html>



