---
title: flag - pwnable.kr
published: true
---

# [](#intro)Introduction

Ahoy, brave CTF adventurers! Today we are going to be dropping Pupa’s card by solving the “flag” CTF at [pwnable](https://pwnable.kr).  Without further ado, let’s see what this challenge is about!


# [](#level-description)Challenge description

The challenge description is:

> Papa brought me a packed present! let's open it.
> 
> 
> Download : [http://pwnable.kr/bin/flag](http://pwnable.kr/bin/flag)
> 
> This is reversing task. all you need is binary
> 

This challenge seems to be only a reverse engineering task, without any source code. What to expect from it?


# [](#approach)Approach mindset

Let’s sharpen up our mindset. Since we don’t have any other information about the challenge, we will need to do a little recon first, by analyzing the binary with GDB. Then, if the flag is inside the binary, we just need to find its address and use `x/1s <address>` to retrieve it in strings format.


## [](#examining-binary)Examining the binary
Once we download the binary, we need to run `chmod +x flag`, then we can use GDB to examine it:

```bash
$ gdb ./flag
...
Reading symbols from ./flag...
(No debugging symbols found in ./flag)
(gdb)
```

Ok, that is problematic… We have no symbols, so there is no way we can disassemble it with GDB. Let’s exit and use other tricks to understand why the symbols are missing. We can analyze it with `strings` command:

```bash
$ strings flag
[...snip...]
USQRH
PROT_EXEC|PROT_WRITE failed.
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
[...snip...]
```

Note that from the huge output we get, this line stands up, showing the file is packed with UPX packer. Alright, this might be the reason why the symbols are missing. Packed files have their symbols stripped, and the only way to read them is by unpacking it. 

After a quick research, we find [this](https://linux.die.net/man/1/upx) article about the `upx` Linux command. This command can be used to unpack executable UPX files, which seems to be our case. We can try using the following command to unpack the file:

```bash
$ upx -d flag
```

This should unpack the `flag` binary and restore the missing symbols. After unpacking, we can analyze the binary again using `file` command to see if the symbols are stripped:

```bash
$ file flag
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=96ec4cc272aeb383bd9ed26c0d4ac0eb5db41b16, not stripped
```

As we can see, the file is not stripped and we can read its symbols! With a little help of GDB, we can disassemble the main function:

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000401164 <+0>:     push   %rbp
   0x0000000000401165 <+1>:     mov    %rsp,%rbp
   0x0000000000401168 <+4>:     sub    $0x10,%rsp
   0x000000000040116c <+8>:     mov    $0x496658,%edi
   0x0000000000401171 <+13>:    call   0x402080 <puts>
   0x0000000000401176 <+18>:    mov    $0x64,%edi
   0x000000000040117b <+23>:    call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:    mov    %rax,-0x8(%rbp)
   0x0000000000401184 <+32>:    mov    0x2c0ee5(%rip),%rdx        # 0x6c2070 <flag>                                                                       
   0x000000000040118b <+39>:    mov    -0x8(%rbp),%rax
   0x000000000040118f <+43>:    mov    %rdx,%rsi
   0x0000000000401192 <+46>:    mov    %rax,%rdi
   0x0000000000401195 <+49>:    call   0x400320
   0x000000000040119a <+54>:    mov    $0x0,%eax
   0x000000000040119f <+59>:    leave
   0x00000000004011a0 <+60>:    ret
End of assembler dump.
```

Aha! As we can see, there is an address which the flag is stored: `0x6c2070`.

## [](#solving)Solving!

Now we can just use `x/1s *0x6c2070` to see the contents allocated in this address:

```bash
(gdb) x/1s *0x6c2070
0x496628:       "UPX...? sounds like a delivery service :)"
```

And there is our flag (:


# [](#conclusions)Conclusion
This was a very simple CTF challenge. By unpacking the packed binary file using the `upx` command, we were able to restore the missing symbols and read them with GDB. After analyzing the binary, we discovered the address where the flag was stored and used `x/1s` command to retrieve the flag: `UPX...? sounds like a delivery service :)`

Enjoy your Pupa card! I heard it gives 400 base HP, so it’s very good for super novice class!

<img src="../figs/pupa.png" alg="pupa card">

I hope you liked this write-up and learned something new. As always, don’t forget to do your **research!**


<a href="/">Go back</a>

