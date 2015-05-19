## SMB Wrapper ##

**smbwrapper** is a python script which provides wrappers around `smbclient` and `winexe` with added functionality and Pass-the-Hash support.

It is intended for penetration testers and security auditors who are targeting Windows/Active Directory environments.

It relies on various external tools such as slighly modified versions of `smbclient-pth`, `winexe-pth`, `xfreerdp` and `socat`. At the moment, they will **only run in Linux x64**.

It also includes various windows executables that are meant to be run on targeted Windows systems, such as [socat for windows](https://github.com/jboecker/dcs-arduino-example/tree/master/socat), [nircmd](http://nirsoft.net/utils/nircmd.html) or *runastask* (see below)

### TL;DR ##

Basic usage:

	$ ./smb.py creds add MYDOMAIN\\Administrator 209C6174DA490CAEB422F3FA5A7AE634 "My Demo User"
	[*] Credentials added and marked as active.

	$ ./smb.py exec 10.10.10.12 whoami
	mydomain\administrator

	$ ./smb.py exec -s 10.10.10.12 whoami
	nt authority\system

	$ ./smb.py exec 10.10.10.12 cmd
	Microsoft Windows [Version 6.1.7601]
	Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

	C:\Windows\system32>

### Help ###

	$ ./smb.py help
	smb.py v0.9 by jrm` - Run stuff remotely - Extract passwords - Pass the Hash

	smb.py -h 			     This help
	smb.py -f <file>		 Specify an alternative credential vault

		The following commands are currently implemented:

		smb.py exec [-s] <ip> [ user ] [ password | ntlm_hash ] <cmd>
		  Execute a command remotely (use "cmd" for a command prompt)

		smb.py upexec [-s] <ip> [ user ] [ password | ntlm_hash ] <localfile.exe [-arg1 [-argx]]>
		  Upload a file and run it remotely with the specified arguments

		smb.py upload [-s] <ip> [ user ] [ password | ntlm_hash ] <localfile> <remotefile>
		  Upload a file to the host

		smb.py download [-s] <ip> [ user ] [ password | ntlm_hash ] <remotefile> <localfile>
		  Download a file from the host

		smb.py scrshot [-s] <ip> [ user ] [ password | ntlm_hash ]
		  Takes a screenshot of the active session

		smb.py vsscpy [-s] <ip> [ user ] [ password | ntlm_hash ] <remotefile> <localfile>
		  Use shadow copies to download a locked file from the host

		smb.py fwrule [-s] <ip> [ user ] [ password ] <add | del> <program path | port number>
		  Creates or remove a rule in the Windows firewall

		smb.py mount <ip> [ user ] [ password ] <share> <localpath>
		  Mount a remote share locally via CIFS (Pass-the-Hash not available)

		smb.py rdp <ip> [ user ] [ password | ntlm_hash ] [ enable | disable ]
		  Open a Remote Desktop session using xfreerdp (Pass-the-Hash = restricted admin)

		smb.py portfwd [-s] <ip> [ user ] [ password | ntlm_hash ] <lport> <rhost> <rport>
		  Forward a remote port to a remote address

		smb.py revfwd [-s] <ip> [ user ] [ password | ntlm_hash ] <lport> <rhost> <rport>
		  Reverse-forward a remote address/port locally

		smb.py mbsa [-s] <ip> [ user ] [ password | ntlm_hash ]
		  Run MBSA on the remote host

		smb.py creds [ list | set | del | use ] <user> <password | ntlm_hash>
		  Manage SMB credentials

		smb.py hash <plaintext>
		  Generate a NTLM hash from a plaintex

		If the command supports it, use the '-s' option to attempt remote LocalSystem elevation.

		Instead of using username+password or username+hash on the commandline,
		you can use the smb creds command to populate the credential vault.

		Usernames must be specified using the DOMAIN\LOGIN syntax.

### Credential management ###

For each command, you can specify the credentials to use on the command line. However, if you choose not to, you can maintain a credential vault.

The `smb.py creds` command allows to view and edit a credential vault in an sqlite database. It is mostly useful when working in an Active Directory environment so that you can retain the domain administrator's credentials across multiple runs without the hassle to specify them on the command line. It also makes to tool more easier and effective to work with.

**Disclamer:** The credentials are stored in clear-text in the sqlite db. Feel free to use NTLM hashes instead of passwords, or not to use this feature at all.

### Writing a quick extension ###

The way **smbwrapper** is designed enables it to be extensible very easily. Just create your own function at the end of the script with a name starting by "smb_".

For example, if you want it to support your *super-cool custom-made antivirus-bypassing* hash dumper program, you would create such a function:

	def smb_hashdump():
		"""
		[-s] <ip> [ user ] [ password | ntlm_hash ]
		Dumps remote password hashes using my prog.
		"""

		set_creds(4)
		check_creds()
		print up_and_exec(['/path/to/my/prog.exe', '--dump'])


`set_creds()` parameter is the minimum length that `sys.argv` can have for the credentials to be read from the vault. If `sys.argv` length is bigger, credentials will be read from the command-line.

`check_creds()` is optional but will prevent running further commands if the credentials don't work.

That's all you need to do.

Note: You could also simply run `smb.py upexec 1.2.3.4 /path/to/my/prog.exe --dump` but creating your own function enables you to add extra functionality easily and can be useful to parse and reuse the output.

### Tools developed for the occasion ###

`runastask.exe` allows to run a GUI program from a non-console session by creating a one-time scheduled task.

It is useful for commands that need access to the user's desktop, such as `smb.py scrshot`. It takes the username to run the task with as an argument. If no matching user desktop is found, it does nothing.