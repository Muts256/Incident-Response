### Files to check in case of suspected intrusion
#### 1. /var/log/secure 
Check this location for SSH logins, sudo commands, and PAM events
  - grep "failed password" \ /var/log/secure
  - grep "accepted" \ /var/log/secure

#### 2. lastb command
Execute lastb command at the prompt. This will display the failed logins with a username and timestamps
  - lastb head -20

#### 3. History
Check the history of commands executed, especially the ones you did not run
  - cd ~
  - cat  .bash_history
  - ls -la .bash_history

#### 4. Check audit.log
The CIS benchmark recommends audit.logs be active

*Display failed audit events*
   - aureport --failed  

*Search for commands that were executed*
   - ausearch -m EXECVE \
     --start recent 
 
#### 5. Cron Persistence
  - crontab -l *list the scheduled tasks*
  - ls -la /etc/cron.d
  - cat /etc/crontab

#### 6. SSH Key Backdoor

find / name \ authorized_keys 2 >/dev/null

#### 7. Check for deleted process
Shows any process that was deleted after execution

ls -la /proc/*/exe \ 2>/dev/null | grep deleted


