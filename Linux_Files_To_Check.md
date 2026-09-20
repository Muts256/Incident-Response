### Files to check in case of suspected intrusion
#### /var/log/secure 
Check this location for SSH logins, sudo commands, and PAM events
  - grep "failed password" \ /var/log/secure
  - grep "accepted" \ /var/log/secure
