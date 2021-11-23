We make network connection in VBox as "Bridge" or "Virtual network"
After it we can scan ourselves with nmap to find Boot2root ip and open ports.

![ip_network](screenshots/ip_network.png)

We found web site under this server.
So we scan 80 and 443 with dirb to find directories. It is output:


![nmap_result](screenshots/nmap_result.png)


Now we have three new points: /fonts (http) and /phpmyadmin, /webmail, /forum (https).
- Fonts are not interesting for us
- phpmyadmin request creditnails. We will not brute it((
- webmail same as above.
- forum works and we can find some useful thigs inside.

On form we see theme by lmezard called "Probleme login?".
It's log and we search for some info. Here we have one string, that seems like password,
if we try it to log in forum, we will succeed. Forum login/pass - lmezard:!q\]Ej?*5K5cy*AJ

After it we can try to Contact and now have lmezard's E-mail adress. If we try to use it to auth /webmail, we will succeed again.
/webmail login/pass - laurie@borntosec.net:!q\]Ej?*5K5cy*AJ

![forum](screenshots/forum.png)

In mailbox we have two messages, one of them includes creds for something called "database".
It is /phpmyadmin login/pass root/Fg-'kKXBj87E:aJ$

![message](screenshots/message.png)

Now is time for Explotation. In phpmyadmin we can make unlimited SQL queries and it means that we could send a payload into a file.
We only should find place where we have access to write files. But we have this place. Look again at dirb output.
Trying several directories and drop php file: In one of directories var/www/forum/templates_c we have enougth rights.

![drop](screenshots/drop.png)

Ok. Now we need reverse shell, we can generate it in base64 with help of 'https://www.revshells.com/'.
And we drop full code with PHP method base64_decode in p.php, start nc, open p.php in browser, improve our shell with python.

![reverse_shell](screenshots/reverse_shell.png)

Now we need to explore system. We look for /home directory, there is dir LOOKATME which contains file password. NICE user login/password lmezard:G!@M6f4Eatau{sF"

![lmezard's_home_dir](screenshots/lmezard's_home_dir.png)

When we logged as lmezard, we found files in his home directory. 'fun' is tar archive, so it will be little more convvenient, to work with it on local machine.
We just copy 'fun' to /forum/templates_c and use chmod 777 (lol). Now we can download file with wget on local machine.

![fun_download](screenshots/fun_download.png)

Then we find a lot pcap files in dir. To deobfuscate it we use sh script. When job is done we use enfile as C-code, compile it and have password, which needed to be cripted with sha-256. hmmm... use sha256 and ssh login/password laurie:330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4
NICE

![pcap_handle](screenshots/pcap_handle.png)

Now we fnally can connect to machine via ssh. We have README, which says we must defuse the bomb and 'bomb'-ELF exutable.
We haven't passion to start binaries named bomb so let's look to strings. We can see all 'phases', that we need to defuse bomb.
We had hint in README, so easily go to stage two. Let's find all passwords with hint. I thought...
But it doesnt work for 2nd level. OK, we download radare2, and here we go.

![turtle](screenshots/turtle.png)

![SLASH_md5](screenshots/SLASH_md5.png)

2nd level. 
We have two simple functions. First, we read six numbers from stdin. If numbers count not equal six, we exlode bomb.
Simply run debugger and watch at cmp instruction. At the end we have 1 2 6 24 120 720

![l2_read_six_nums](bomb/l2_read_six_nums.png)

3d level.
Func want t numbers and letter. OKAY. It is only begin. We see a lot of jumps fahrer from begin. There is switch-case construction.
It depend from first number value. So we try everything from first condition and we're good.
In the HINT our letter is b, so second group of values is ours. 1 b 214. OK

![l3_beginning](bomb/l3_beginning.png)
![l3_general](bomb/l3_general.png)

4d level.
Owh. We're bad. We have recoursive function here. It will be hard. 
We have internet, so we can install ghydra with 'r2pm --ci r2ghydra'.
Я не смог установить гидру и там пищдец, меня это заебало внатуре ахахах




And in thor acc we have turtle and README. README doesn't tell anything usefull, so we look at file. It's text with directions of tutle. In Mother Russia we did this things it school.ON PAPER. And now We just write python script.

![turtle.dir](screenshots/turtle.png)
 
