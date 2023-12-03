---
title: fd - pwnable.kr
published: true
---

# [](#intro)Introduction

[Pwnable](https://pwnable.kr) is a website for cybersecurity enthusiasts willing to challenge themselves by solving different kinds of CTFs. I've come across it in one of my lazy YT shorts watching moments, where I found out about someone solving these CTFs. As an enthusiast myself, I thought: well, let's give it a shot. 

To my surprise, not only did it look pretty fun, but the level tag images are the different Ragnarok Online monsters cards. Ok! You got me here already! As someone with the alias 'Cecil Daemon', I felt obligated to start cracking each level.

This post is about solving the very first level, named 'fd'. Let's drop our Poring card!

# [](#level-description)Challenge description
> Mommy! what is a file descriptor in Linux?
>
> try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
> https://youtu.be/971eZhMHQQw

> ssh fd@pwnable.kr -p2222 (pw:guest)

# [](#approach)Approach mindset

Ok, I'll be spilling some gold here by letting you all know how I approach CTF challenges with a mindset that rarely fails me. First off, I'm not a C/C++ pro developer, but I have my fair share of coding in these languages. However, technical jargon was not always my strength. "_What the f*** is a file descriptor_" was my first thought. Little did I know that I knew what it was, but not from its name.

## [](#mindset-step1)Step 1 - Understanding basic concepts

Think of it like this: if we don't know what a file descriptor is, we'd better step back for a moment and learn about it. This is the first step - understanding the problem. In fact, I didn't learn this doing CTFs.  I learned it while I was pursuing my totally unrelated Master's Degree in Physics. The word for this is **research**. 

Research is always your best friend here, and the more we are comfortable at learning stuff, reading documentation and practicing what we've learned, the more easily these challenges blossom.


### [](#fd-definition)What is a File Descriptor?

File Descriptors are, put in simple terms, non-negative integers - more specifically 0, 1 and 2 - that are shorthands for three important concepts: 0 for Standard Input (stdin), 1 for Standard Output (stdout), and 2 for Standard Error (stderr). The table below summarizes what each of these terms mean

| Descriptor name       | Short name         | Description                   | Descriptor integer
|:----------------------:--------------------|:------------------------------|:-----------
| Standard in           | stdin              | Input from keyboard           | 0
| Standard out          | stdout             | Output from console           | 1 
| Standard err          | stderr             | Error output to the console   | 2

A simple example in the Linux terminal would be redirecting the descriptors to programs or files. For example, typing a wrong or nonexistent command - like 'dsasd' - in the terminal will raise a "command not found" error:

```bash
kaizen@celestial ~ $ dsasd
bash: dsasd: command not found
```

 However, if we redirect our stderr to `/dev/null`, we should see no error popping up:

 ```bash
kaizen@celestial ~ $ dsasd 2>/dev/null
kaizen@celestial ~ :( $ 
 ```

The same thing is true for our stdout descriptor. Running `ls -la` prints all contents in the current directory to our stdout descriptor:

```bash
kaizen@celestial /tmp/fd $ ls -la
total 0
drwxr-xr-x  5 kaizen users 160 Dec  1 23:39 .
drwxrwxrwt 17 root   root  860 Dec  1 23:39 ..
-rw-r--r--  1 kaizen users   0 Dec  1 23:39 file1
-rw-r--r--  1 kaizen users   0 Dec  1 23:39 file2
-rw-r--r--  1 kaizen users   0 Dec  1 23:39 file3
drwxr-xr-x  2 kaizen users  40 Dec  1 23:39 test1
drwxr-xr-x  2 kaizen users  40 Dec  1 23:39 test2
drwxr-xr-x  2 kaizen users  40 Dec  1 23:39 test3
```

We could redirect the stdout to a file, so that the output will be saved into it:

```bash
kaizen@celestial /tmp/fd $ ls -la 1>stdout
kaizen@celestial /tmp/fd $ cat stdout
total 0
drwxr-xr-x  5 kaizen users 180 Dec  1 23:41 .
drwxrwxrwt 17 root   root  860 Dec  1 23:39 ..
-rw-r--r--  1 kaizen users   0 Dec  1 23:39 file1
-rw-r--r--  1 kaizen users   0 Dec  1 23:39 file2
-rw-r--r--  1 kaizen users   0 Dec  1 23:39 file3
-rw-r--r--  1 kaizen users   0 Dec  1 23:41 stdout
drwxr-xr-x  2 kaizen users  40 Dec  1 23:39 test1
drwxr-xr-x  2 kaizen users  40 Dec  1 23:39 test2
drwxr-xr-x  2 kaizen users  40 Dec  1 23:39 test3
```

Finally, stdin is exactly what we type into the terminal from our keyboard. An example would be passing input to a command, such as:

```bash
kaizen@celestial /tmp/fd $ echo "ls" | bash
file1  file2  file3  stdout  test1  test2  test3
```

Here, our stdin is the string `"ls"`, which is being passed to our bash interpreter.


## [](#mindset-step1) Step 2 - Understanding the problem

Now that we know what a file descriptor is and how to use it, we can finally start the CTF.

- _Tip: It's good practice to check the CTF challenge before doing the research. In this case, however, since the challenge description mentioned something 'new' right from the bat, I decided to take the step back before actually checking the CTF problem. Most of the time, we need to first understand the proposed CTF challenge and then conduct the necessary research._

To start the CTF, we need to ssh into the machine. This can be done with the command:

`ssh fd@pwnable.kr -p2222`

You will be prompted for the password, which is `guest`. After successfully connecting to the machine, we can simply run ls -l to see what we have in our home directory:

```bash
fd@pwnable:~$ ls -l
total 16
-r-sr-x--- 1 fd_pwn fd   7322 Jun 11  2014 fd
-rw-r--r-- 1 root   root  418 Jun 11  2014 fd.c
-r--r----- 1 fd_pwn root   50 Jun 11  2014 flag
```

Note that we have a C code `fd.c`; a binary file `fd` and a text file `flag`. Let's see who we are in the machine:

```bash
fd@pwnable:~$ whoami
fd
```

Okay, based on the `whoami` command, we are not able to simply read `flag`, as we are not part of the `root` group, nor are we `fd_pwn` user. However, we can read `fd.c` and execute `fd`. We can `cat fd.c` to see its contents:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```

This program seems to be taking a single-number argument in `argv[1]` and evaluating the expression `atoi(argv[1]) - 0x1234`, storing the result into the variable called `fd`. The `read` C function takes a file descriptor as first argument, which means it will read what is passed in that specific descriptor. This is stored in the `buf` buffer variable. 

The `strcmp` function will compare the string stored in the buffer with "LETMEWIN\n", and if they are equal, _i.e._, `strcmp` returns 0, the if statement becomes `!0` (C equivalent to true).

The key to solve this problem is to pass an `argv[1]` that will evaluate `fd` to a file descriptor we can control containing the string "LETMEWIN".

## [](#mindset-step3)Step 3 - Crafting the attack

Now that we understand the basic concepts and the CTF problem, we need to think of a plausible attack vector. The easiest one in this case is to control the stdin descriptor, which is one that is hard to defend against. Looking at our table, this file descriptor is represented by the integer 0. So we need to pass an `argv[1]` that will evaluate the `fd` variable to 0. Note that:

`fd = atoi(argv[1]) - 0x1234`

which is telling us that the number we pass will be subtracted by `0x1234`, a hexadecimal value. We can use [this](https://www.rapidtables.com/convert/number/hex-to-decimal.html) website to convert hex to decimal. Note that the hexadecimal number 0x1234 is 4660 in decimal. So, if we need `fd` to be 0, we need to pass 4660 as the argument. If we did everything correctly, this argument will prompt us the `read` function to input a stdin value, rather than just telling us to learn about Linux file IO, as we get if we pass a random number:

```bash
fd@pwnable:~$ ./fd 123
learn about Linux file IO
```

However, passing 4660, the code starts expecting another input!

```bash
fd@pwnable:~$ ./fd 4660
asdasd
learn about Linux file IO
```

Promising!

## [](#mindset-step4) Step 4 - Solving!

I think the solution becomes self explanatory at this point. If not, it may be a good idea to re-read this post! 

When the code expects the second input, which is the stdin descriptor, we need to pass the string "LETMEWIN" so that `strcmp` evaluates to `!0`, triggering the if statement that reads the flag:

```bash
fd@pwnable:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```

Amazing! Enjoy your Poring card drop. It was well deserved!

### [](#solution2) Another solution

Another way to solve this is piping the "LETMEWIN" string directly to the program. This is similar to the example we gave about stdin descriptor `echo "ls" | bash`, which executes the `ls` command. 

Here, we basically do the same thing, but passing "LETMEWIN" to `./fd 4660`

```
fd@pwnable:~$ echo "LETMEWIN" | ./fd 4660
good job :)
mommy! I think I know what a file descriptor is!!
```

# [](#conclusions) Conclusion

Solving CTFs and anything in life, for that matter, comes down to doing a good research beforehand.

In this CTF, we've learned what file descriptors are, as well as understood some C code analysis on the way.

Thanks for sticking 'til the end. I hope you enjoyed it! And remember, always do your **research!**

<a href="/">Go back</a>



