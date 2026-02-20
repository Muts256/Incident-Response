## Table of Contents

- [Scenario](#scenario)
- [Technology](#technology)
- [Prerequisites](#prerequisites)
- [NIST SP 800-61 Incident Response Lifecycle](#nist-sp-800-61-incident-response-lifecycle)
  - [The Attack](#the-attack)
  - [Preparation](#preparation)
  - [Detection and Analysis](#detection-and-analysis)
  - [Containment, Eradication, and Recovery](#containment-eradication-and-recovery)
  - [Post-Incident Activity](#post-incident-activity)
- [Lessons Learned](#lessons-learned)


### Scenario

“Script execution attacks” occur when a bad actor infects your endpoint with malware that uses a “script interpreter” (in this case, AutoIt.exe) to automatically launch malicious programs within the target machine, silently. This typically happens when you download this malware from a website or click a malicious link.

This lab involves creating MDE detection rules to detect the attack, setting up a VM to be vulnerable to it, using some tools to monitor the VM, and finally executing the malicious script. Finally, conduct a basic incident response based on what was detected using NIST 800-61.

### Technology:
  - Microsoft Defender for Endpoint (MDE)
  - Virtual Machine (VM)
  - Sentinel
  - AtomicRedTeam Scripts
  - Git

### Prerequisites

Spin up a VM, disable the firewall, and the Network Security Group (NSG) to allow download of the scripts. 

Onboard your VM to Microsoft Defender for Endpoint (EDR) to enable detection. Download the script from this site

```
https://sacyberrange00.blob.core.windows.net/mde-agents/Windows-10-and-11-GatewayWindowsDefenderATPOnboardingPackage.zip
```
Install Git.

```
https://git-scm.com/downloads/win
```
Ensure the setting for adjusting your environment path is at Git from the command line and also from 3rd party software 

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At13.png)

### NIST SP 800-61 Incident Response Lifecycle
1. **Preparation**
2. **Detection & Analysis**
3. **Containment, Eradication, & Recovery**
4. **Post-Incident Activity**

*NB: Configure the detection rules before executing the attack*

---

### The Attack

Execute the following commands one after the other 

1. This command downloads the Atomic Red Team repository from GitHub to your local system.
```
git clone https://github.com/redcanaryco/atomic-red-team.git
```

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At1.png)

2. Ensure you are in the directory where atomic-red-team is downloaded
   
```
cd C:\Users\labuser1\atomic-red-team
```

3. This sets the environment variable and points it to the atomic script from the correct folder (Atomics)
```
$env:PathToAtomicsFolder = "C:\Users\labuser1\atomic-red-team\atomics\"
```

4. Installs a PowerShell module and allows the module to overwrite existing commands with the same names from other modules.
```
Install-Module -Name Invoke-AtomicRedTeam -Force -AllowClobber
```
![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At2.png)

5. This command loads the Invoke-AtomicRedTeam module
```
Import-Module Invoke-AtomicRedTeam
```
6. This command temporarily disables script execution restrictions for the current PowerShell session only, allowing scripts to run without being blocked.

```
Set-ExecutionPolicy Bypass -Scope Process -Force
```
7. The command prepares the system to run Atomic Red Team tests for MITRE ATT&CK technique T1059 (Command and Scripting Interpreter) by downloading or installing any required prerequisites.
```
Invoke-AtomicTest T1059 -GetPrereqs -PathToAtomicsFolder "C:\Users\labuser1\atomic-red-team\atomics\"
```

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At4.png)

8. The command executes Atomic Red Team adversary simulation tests for MITRE ATT&CK technique T1059 (Command and Scripting Interpreter).

```
Invoke-AtomicTest T1059 -PathToAtomicsFolder "C:\Users\labuser1\atomic-red-team\atomics\"
````
![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At5.png)

If and when the calculator app is launched, the script was successfully executed

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At6.png)

---

### Preparation

The Preparation Phase establishes the foundational capabilities to effectively manage security incidents. This includes developing detection rules to identify potential compromises, along with creating policies, assembling teams, and provisioning tools. The goal is to ensure the organization is ready to rapidly detect, analyze, and contain incidents when they occur.

#### Detection Rules

Query 1
```
DeviceProcessEvents
| where DeviceName contains "mm-atomicred-vm"
| where FileName contains ".exe"
| where ProcessCommandLine contains "calc.au3"
```
The query detects execution of a Windows executable associated with an AutoIt script on a red-team test system.

This activity may indicate:
  - Script-based malware execution
  - Living-off-the-land or trusted scripting abuse
  - Adversary simulation using Atomic Red Team

AutoIt is a legitimate automation tool, but it is frequently abused by attackers to:
  - Execute malicious payloads
  - Bypass application allowlists
  - Obfuscate malicious logic inside compiled executables

##### MITRE ATT&CK mapping
T1059 – Command and Scripting Interpreter
  - General abuse of scripting engines.

##### Detection logic.

This query is useful for:
  - Detecting AutoIt-based malware
  - Monitoring Atomic Red Team simulations
  - Hunting for script execution masquerading as benign executables
  - Enhancing visibility into command-line–based abuse

Query 2
```
DeviceProcessEvents
| where DeviceName == "mm-atomicred-vm"
| where InitiatingProcessParentFileName contains "AutoIt3.exe"
| where FileName contains "calc.exe"
```
This query detects AutoIt launching a child executable on a monitored system, indicating script-based execution of a payload.

Attackers frequently use AutoIt to:
  - Execute secondary payloads
  - Hide malicious logic inside compiled scripts
  - Bypass application allowlisting
  - Blend in with legitimate automation tools

##### MITRE ATT&CK mapping
T1059 – Command and Scripting Interpreter
  - General abuse of scripting engines.


##### Detection logic

This rule is useful for:
  - Detecting AutoIt-based malware execution
  - Monitoring Atomic Red Team simulations
  - Hunting for script-spawned executables
  - Identifying living-off-the-land scripting abuse


Query 3
```
DeviceProcessEvents
| where DeviceName == "mm-atomicred-vm"
| where FileName contains "powershell.exe"
| where ProcessCommandLine has_any ("autoit3", "getfile.pl")
```
This query detects PowerShell being used in conjunction with AutoIt or Perl-based file retrieval scripts, suggesting script-based execution or payload staging.

Attackers often use scripting tools together, linking them in sequence to :
  - Download payloads
  - Execute secondary malware
  - Evade detection by blending in with legitimate scripting activity
  - Live off the land using trusted interpreters

##### MITRE ATT&CK mapping
T1059 – Command and Scripting Interpreter
  - General abuse of scripting engines.


##### Detection logic

This query is useful for:
  - Detecting multi-stage script-based attacks
  - Monitoring Atomic Red Team adversary simulations
  - Hunting for PowerShell abuse combined with secondary tools
  - Identifying living-off-the-land attack chains

Query 4
```
DeviceFileEvents
| where DeviceName == "mm-atomicred-vm"
| where FileName has "autoit" and FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
```
The detects PowerShell creating or modifying AutoIt-based executables on a monitored system, indicating potential payload staging or script-based malware execution.

Attackers commonly use PowerShell to:
  - Download or generate AutoIt executables
  - Stage payloads for later execution
  - Evade detection by using trusted scripting tools

##### MITRE ATT&CK mapping
T1059 – Command and Scripting Interpreter
  - General abuse of scripting engines.

##### Detection logic

This query is useful for:
  - Detecting AutoIt-based malware staging
  - Monitoring PowerShell-driven payload creation
  - Hunting script-based attack chains
  - Supporting Atomic Red Team testing and validation

Create Detection rules in MDE

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At15.png)


---

### Detection and Analysis

The Detection & Analysis phase is the critical "trigger point" of the NIST Incident Response lifecycle. It focuses on the shift from normal operations to active incident management, where a potential security event is identified, validated, and assessed.

The primary goal of this phase is to determine whether a security event has occurred accurately and, if so, to analyse its scope, impact, and urgency to enable an effective response.

##### Key Activities
This phase involves a continuous, often rapid, series of steps:

Detection: Identifying potential incidents through tools (IDS/IPS, SIEM, EDR), user reports, or threat intelligence feeds.

Triage & Validation: Filtering out false positives and confirming that a genuine security incident is taking place.

Analysis: Investigating the "who, what, when, where, and how" of the incident to understand:

  - Tactics, Techniques, and Procedures (TTPs): How the attacker operates.

  - Scope: Which systems, data, and users are affected.

  - Impact: The potential or actual business damage (data loss, financial, reputational).


  - Attribution & Intent: If possible, identifying the threat actor and their goals.

  - Prioritisation & Documentation: Assigning a severity level based on impact and urgency, and formally logging all findings to create the initial incident record.

With the successful launch of the calculator app, check if any of the rules were triggered

2 rules were triggered

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At7.png)

Analysis showed that for query 1 a powershell and AutoIt3 processes were created
```
DeviceProcessEvents
| where DeviceName contains "mm-atomicred-vm"
| where FileName contains ".exe"
| where ProcessCommandLine contains "calc.au3"
```

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At8.png)

For Query 2 a calc process was created 

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At9.png)


Query 3

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At10.png)


Query 4

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At11.png)




Check if there was any remote connection

```
DeviceNetworkEvents
| where DeviceName == "mm-atomicred-vm"
| where RemoteIP != ""
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessCommandLine has_any ("powershell", "Invoke-WebRequest")
```
The query detects successful network connections made by PowerShell-based commands on a specific VM, which may indicate payload download, C2 communication, or script-based data retrieval.

This query is useful for detecting:

  - Malicious PowerShell web requests

  - Initial payload delivery

  - Living-off-the-land attacks (LOLBins)

  - Post-exploitation tooling downloads

![image alt](https://github.com/Muts256/SNC-Public/blob/c7aedabd3a0bcbeb395401acd2f0bb9b8e11c80b/Images/Atomic-Red-Team/At12.png)

According to the logs, there was no connection.

---

### Containment, Eradication, and Recovery 

#### 1. Containment

**Objective:** Limit the damage and prevent the incident from spreading.

**Activities:**

- Isolate affected systems from the network.
- Disable compromised accounts.
- Block malicious IPs or domains.
- Apply temporary firewall or access control rules.

**Goal:** Prevent further data loss or system compromise while investigation continues.

In this case, the device was isolated 

#### 2. Eradication

**Objective:** Remove the root cause of the incident.

**Activities:**

- Identify and remove malware, malicious scripts, or unauthorized accounts.
- Close exploited vulnerabilities.
- Apply patches and configuration changes.
- Clean up persistent threats or backdoors.

**Goal:** Ensure that the threat no longer exists in the environment.

An antivirus scan was started

#### 3. Recovery

**Objective:** Restore affected systems and services to normal operation safely.

**Activities:**

- Restore systems from trusted backups.
- Monitor systems closely for recurrence.
- Validate system integrity and functionality.
- Gradually reconnect systems to the production network.

**Goal:** Resume normal business operations without reintroducing the threat.

---

### Post-Incident Activity 

Objective
Analyze the incident response effort, capture lessons learned, and improve the organization’s security posture to prevent similar incidents in the future.


#### Key Activities

#### Lessons Learned Review
- Conduct post-incident meetings with all relevant stakeholders.
- Identify what worked well and what did not during detection, analysis, and response.

Two detection rules did not trigger; during this phase, the rules are reviewed to determine why they failed and are fine-tuned to ensure they function as intended.

#### Root Cause Analysis
- Determine how the incident occurred.
- Identify gaps in controls, monitoring, or procedures.

#### Documentation and Reporting
- Finalize incident reports and timelines.
- Document indicators of compromise (IOCs), tactics, techniques, and procedures (TTPs).

#### Improve Security Controls
- Update detection rules and alerting logic.
- Enhance logging, monitoring, and visibility.
- Strengthen access controls and authentication mechanisms.

#### Policy and Procedure Updates
- Update incident response playbooks and escalation procedures.
- Refine vulnerability management and patching processes.

#### Training and Awareness
- Provide targeted training based on findings.
- Improve user awareness to reduce human-related risks.


#### Goal

Reduce the likelihood and impact of future incidents by continuously improving the incident response capability.


### Lessons Learned

- Detection rules may not always trigger as expected, highlighting the need for continuous validation and tuning.
- High-fidelity detections require contextual correlation across process, file, network, and logon telemetry.
- Living-off-the-land tools (e.g., PowerShell, Bash, AutoIt, Azure CLI) can be abused and may evade static detections.
- Insider threat activity can closely resemble legitimate user behavior, emphasizing the importance of least privilege and user behavior monitoring.
- Mapping detections to MITRE ATT&CK helps identify coverage gaps and improves investigation clarity.
- Adversary simulation using Atomic Red Team is effective for validating SOC detection readiness.
