---
title: collision - pwnable.kr
published: true
---

# [](#intro)Introduction

Let's continue with our card dropping adventures on [Pwnable](https://pwnable.kr). This time, we will be dropping Fabre's card. If you haven't checked my first blog post solving 'fd' on Pwnable, go check it out [here](fd-pwnable).

Let's start!

# [](#level-description)Challenge description
> Daddy told me about cool MD5 hash collision today.
> I wanna do something like that too!
>
> ssh col@pwnable.kr -p2222 (pw:guest)

# [](#approach)Approach mindset

Simarly to the last CTF challenge, we shall tackle this one by first understanding what is a _MD5 hash collision_ before we even ssh into the machine.

## [](#mindset-step1)Step 1 - Understanding basic concepts

MD5 hash collision is a well defined attack, with many different articles and papers explaining the concept. For instance, [D. Kashyap](https://scholarworks.sjsu.edu/cgi/viewcontent.cgi?referer=&httpsredir=1&article=1020&context=etd_projects) has a complete dedicated Master's thesis on this, which might be more than enough for us to understand this attack.

In it, we can see that the definition of a collision attack is: _"Finding two different messages that gives the same hash value"_. 

The idea is the following: in a collision attack, the goal is to find two distinct messages $M$ and $M'$ that produce the same hash value $h$. This can be conceptualized by modifying subcomponents of $M$ - say $M_0$ and $M_1$ - to create the new message $M'$ - composed of $M_0'$ and $M_1'$ - such that the hash of $M'$ equals the hash of $M$.

The relations between the two subcomponents of $M$ and $M'$ are

$$M_0' = M_0 + \Delta M_0$$

and

$$M_1' = M_1 + \Delta M_1$$

where $\Delta M_0 = M_0' - M_0$ and $\Delta M_1 = M_1' - M_1$ are the bitwise difference of the two sub-message pairs. These two, $\Delta M_0$ and $\Delta M_1$, are typically complex to calculate, but if succeeded, they do compromise the integrity of systems using MD5 by allowing different inputs to be treated as identical. 

While I doubt these calculations are going to be related to this CTF's, it is good practice to understand the broader concept of collisions, as it might help us solve the challange. If you are interested in reading more about the specifics of MD5 collision, check it out [D. Kashyap](https://scholarworks.sjsu.edu/cgi/viewcontent.cgi?referer=&httpsredir=1&article=1020&context=etd_projects) thesis.

## [](#mindset-step2)Step 2 - Understanding the problem

Alright, let's ssh into the machine and take a look around! We can ssh with the command:

`ssh col@pwnable.kr -p2222`

Remember to pass the correct password, which is `guest`. As soon as we land into the machine, we can run the `ls -l` command. This gives us:

```bash
col@pwnable:~$ ls -l
total 16
-r-sr-x--- 1 col_pwn col     7341 Jun 11  2014 col
-rw-r--r-- 1 root    root     555 Jun 12  2014 col.c
-r--r----- 1 col_pwn col_pwn   52 Jun 11  2014 flag
```

Let's take a look at the `col.c` script:

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

Hmmm. Interesting. This looks like a simple password verification code, which we can use by running `./col <passcode>`. Let's break it down:

1. First, the code checks if our `<passcode>` input has length 20. If not, then it warns us that it must have length 20. 

2. If our passcode has 20 bytes, then the code will pass it to the `check_password` function. If the output from the `check_password` equals `hashcode = 0x21DD09EC`, then we solve the challenge. 

Let's understand now what the `check_password` function does:

1. First, it initializes an integer pointer `ip` that references each 4 bytes of `<passcode>` as an integer. 

2. It then initializes `res` integer as 0, thus interpreting the input string as an array of integers. This means that each 4 bytes of the passcode are grouped together and interpreted as one integer.

3. Finally, it returns `res` with the hexadecimal representation of the `<passcode>` we provided.

Note that we need to pass a `<passcode>` that is represented in its hexadecimal value as `hashcode`. This is where the collision happens! Note that the `<passcode>` must have 20 bytes in length. When `check_password` is called, it will break our `<passcode>` into 5 different integer values that must add up to `hashcode`. That means the `<passcode>` must add up to `0x21DD09EC` within 5 iterations. For that matter, we need to divide `0x21DD09EC` by 5, and the result must be our 4 bytes sub-messages of our 20 bytes `<passcode>`.

We can use [this](https://www.calculator.   net/hex-calculator.html) hex calculator to properly find the division of `hashcode` by 5:

$$\frac{0\text{x21DD09EC}}{5} = 0\text{x6C5CEC8} \text{ remainder : 4}$$

The division is not exact, which means we have a leftover term to be added in order to retrieve the exact value of `hashcode`. This means that:

$$\text{remainder} = 0\text{x21DD09EC} - 4*0\text{x6C5CEC8}$$

Which is the same as

$$\text{remainder} = 0\text{x21DD09EC} - 0\text{x1B173B20} = 0\text{x6C5CECC}$$

So, if our calculations are correct, we have:

$$\text{hashcode} = 0\text{x21DD09EC} = 4*0\text{x6C5CEC8} + 0\text{x6C5CECC}$$

In other words, our `<passcode>` must have four 4 bytes strings with value `0x6C5CEC8` collided with one 4 bytes integer with value `0x6C5CECC`. This will sum up to a 20 bytes integer and `check_password` will evaluate it to the `hashcode`.

The only thing left to be done here is to successfully find a way to represent the `<passcode>` as a 20 byte integer that will be converted the way we calculated.

### [](#considerations-step2) Considerations

It is important to consider here the endianess - byte order - used by the system. The endianess refers to the order in which bytes are stored for multi-byte data types like integers in memory. There are two types of endianess:

1. **Little endian**: in little endian systems, the least significant byte (LSB) of a word is stored at the smallest memory address, and the most significant byte (MSB) is stored at the highest address. For example, the hexadecimal value $0\text{x12345678}$ will be stored in memory as 78, 65, 43, and 21. 

2. **Big endian**: in big endien systems, the LSB of a word is stored at the highest memory address, and the MSB is stored at the smallest address. For example, the same hexadecimal value $0\text{x12345678}$ will be stored in memory as 12, 34, 56, and 78. 

## [](#mindset-step3)Step 3 - Crafting the attack

The first think we have to do is figure out how to write our `<passcode>` such that it is translated to the `hashcode` value, represented in our aforementioned calculations. In our local machine, we could write a Python script that does this. Let's assume little endian here, since most x86 architectures are little endian.

```python
bytes1 = b'\xC8\xCE\xC5\x06'
bytes2 = b'\xCC\xCE\xC5\x06'

passcode = 4*bytes1 + bytes2

assert len(passcode) == 20, "Passcode does not meet criteria"

print(passcode)
```

Running the code, we assert that the lenght of the passcode is 20 and the result is:

```bash
kaizen@celestial /tmp/col $ python3 col.py 
b'\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xc8\xce\xc5\x06\xcc\xce\xc5\x06'
```

Alright! That seems to be working! But how can we run this directly in the command line instead? I assume we won't have permissions to write a Python script inside the CTF machine... Let's check:

```
col@pwnable:~$ python3 -c "print('hi mom')"
hi mom
```

Ok, we are able to run a command line Python snippet. Let's solve this bad boy!

## [](#mindset-step4)Step 4 - Solving!

I've tried a few different approaches before actually finding the write payload. Let's check what I've tried and why it has failed.

### Attempt 1
My first attempt was to pass a string that had the Python snippet embedded with it. Here is what I got:

```bash
col@pwnable:~$ ./col "python3 -c 'print(4 * \xc8\xce\xc5\x06+\xcc\xce\xc5\x06)'"
passcode length should be 20 bytes
```

Yep. That did not work. I think the problem here is that the `col` binary is interpreting all of the payload as my passcode, and not actually running the `python3` command. Let's move to my second attempt.

### Attempt 2

Let's try command substitution, which is basically telling the shell to store the result of the `python3` command into a variable and then pass it to `col`. However, that also did not work:

```bash
col@pwnable:~$ ./col "$(python3 -c "print(4 * b'\xc8\xce\xc5\x06' + b'\xcc\xce\xc5\x06')")"
passcode length should be 20 bytes
```

Which made me think that the problem was the quotation order. In this payload, I'm using double quotes for two different sets of the payload, which might confuse the shell. Let's see my third attempt.

### Attempt 3

My third attempt was trying to use quote escaping as an alternative for one of the pairs of double quotes:

```bash
col@pwnable:~$ ./col "$(python3 -c 'print(4 * b'\''\xc8\xce\xc5\x06'\'' + b'\''\xcc\xce\xc5\x06'\'')')"
passcode length should be 20 bytes
```

As we can see, that did not work either.

## Attempt 4

I was getting tired of counting single, double quotes, and escaped single quotes. Maybe I should take a different approach. Maybe the problem wasn't the quotation, but the way `print` function outputs raw bytes. 

So I thought... What if I forced the print to correctly pass the raw bytes using `sys.stdout` buffer? Well, let's see:

```bash
col@pwnable:~$ ./col "$(python3 -c 'import sys; sys.stdout.buffer.write(4 * b"\xc8\xce\xc5\x06"+ b"\xcc\xce\xc5\x06")')"
daddy! I just managed to create a hash collision :)
```

It worked! But why? We have the following two answers:

1. Using `sys.stdout.buffer.write` enforces raw bytes to be written directly to stdout descriptor. This avoids any additional characters that `print` might add.

2. We ensured that the entire Python command is enclosed in single quotes, and the byte strings within the Python command are enclosed in double quotes.

Enjoy your Fabre card! This one was harder than the Poring one.

# [](#conclusions) Conclusion

In this CTF we learned a lot! Not only we got a bit of taste of what MD5 hash collisions were theoretically, but also got a small environment to practice a way simplified version of this. Although the CTF was not actually related to MD5 hash collision, the concept used to solve it is very similar - but oversimplified - to this much more complex topic.

We also used a little endian byte order to solve this, which is something to keep in mind. Big endian would not have worked in a x86 architecture, and our guess to use little endian was initially correct!

Not only that, we also needed to think of different ways of crafting a good payload so that the hexadecimal integers were actually interpreted by the `col` binary. This shows why persistence and resilience is a mastermind skill to have as a hacker.

This is exactly what a hacker does: finds its way through. We had the answer, we just needed to find an open window, and down the rabbit hole we go!

Thanks for sticking until the end. It was a nice ride! And remember, always do your **research!**

<a href="/">Go back</a>

