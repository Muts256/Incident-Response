## Table of Contents

- [What is Impossible Travel?](#what-is-impossible-travel)
- [Scenario](#scenario)
- [Preparation](#preparation)
- [Detection and Analysis](#detection-and-analysis)
- [Containment, Eradication, and Recovery](#containment-eradication-and-recovery)
- [Post-Incident Activity](#post-incident-activity)
- [Lessons Learned](#lessons-learned)


## What is Impossible Travel?

**Impossible Travel** is a security detection technique used to identify potentially compromised user accounts based on **geographic inconsistency in authentication events**.

### How it works
An alert is triggered when:

- A user logs in from **Location A**
- Then logs in again from **Location B**
- Within a time window that is **physically impossible** to travel between  
  *(e.g. Ireland → Singapore in 20 minutes)*

### What this may indicate:
 Impossible Travel detections often point to:

- **Stolen credentials**
- **Session hijacking**
- **Token theft**
- Use of **VPNs, proxies, or anonymization services** by an attacker

## Why Impossible Travel Matters

### Common attacker behaviors
Attackers frequently:

- Use credentials stolen via **phishing**
- Authenticate from **cloud infrastructure** or **foreign IP ranges**
- Bypass MFA using **token replay** or **MFA fatigue attacks**

### Why this detection is effective
Impossible Travel is effective because:

- It focuses on **behavior**, not malware
- It detects **valid logins** being used maliciously
- It works especially well in **cloud-first and identity-focused attack scenarios**

### MITRE ATT&CK Mapping

| Detection Name      | MITRE Tactic        | MITRE Technique | Description |
|--------------------|---------------------|-----------------|-------------|
| Impossible Travel  | Credential Access / Initial Access | T1078 - Valid Accounts | Detection of logins from geographically distant locations within an impossible timeframe, indicating potential credential compromise |

[Back to the Top](#table-of-contents)

---

## Scenario

Design a Microsoft Sentinel scheduled analytics rule using Log Analytics to detect anomalous user logins across multiple locations within a defined time window. For example, trigger an alert when a user authenticates from two or more distinct geographic regions within 3 days.

The NIST Incident Response lifecycle provides a structured and repeatable approach for investigating **impossible travel** activity by guiding how alerts are handled from initial readiness through post-incident improvement. When a user account is observed authenticating from geographically distant locations within an unrealistic time frame, the lifecycle ensures the activity is investigated consistently, responded to appropriately, and reviewed for future improvement.

Each phase of the lifecycle supports the investigation process:

- **Preparation**
- **Detection and Analysis**
- **Containment, Eradication, and Recovery**
- **Post-Incident Activity**

Using this framework helps ensure impossible travel alerts are handled efficiently while maintaining visibility, accountability, and continuous improvement across the security program.

---

## Preparation

The Preparation phase focuses on establishing the tools, processes, and policies necessary to detect and respond to impossible travel activity effectively. This includes ensuring that authentication and logon data are collected and ingested into a SIEM or log analytics platform, such as Microsoft Sentinel, with sufficient detail to identify geographic locations of logins.

Key preparation activities involve enabling identity and access monitoring, configuring alerts for anomalous logins, defining thresholds for impossible travel detection, and training analysts on how to interpret login patterns and location data. Proper preparation ensures that when an impossible travel alert occurs, the incident can be quickly validated, assessed, and investigated with minimal confusion or delay.

In Sentinel, navigate to the Log Analytics workspace, click on Create

![image alt](https://github.com/Muts256/SNC-Public/blob/d3658edbf27af6e52e94d95f999b99bde2a02a76/Images/Incident-Response/Brute-Force/In1.png)

In the Create New Scheduled rule page, give the rule a name and description

![image alt](https://github.com/Muts256/SNC-Public/blob/d3658edbf27af6e52e94d95f999b99bde2a02a76/Images/Incident-Response/Possible-Impossible-Travel/Im1a.png)

Set the Query logic 

```
let TimePeriodThreshold = timespan(3d); 
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed

```

Fill in the Alert Enhancement fields

![image alt](https://github.com/Muts256/SNC-Public/blob/d3658edbf27af6e52e94d95f999b99bde2a02a76/Images/Incident-Response/Possible-Impossible-Travel/Im2.png)

[Back to the Top](#table-of-contents)

---

## Detection And Analysis

During the **Detection and Analysis** phase, the SOC investigates an
**Impossible Travel** alert generated by the SIEM.

The alert is triggered when a user account successfully authenticates from two geographically distant locations within a short timeframe, where physical travel is not feasible.

The analyst performs the following actions:

- Review authentication timestamps and source locations
- Validate that sign-ins occurred within a short time window (e.g. 15–60 minutes)
- Confirm successful authentication events only
- Assess MFA status and authentication method used
- Analyse device information and sign-in context
- Check IP reputation and ASN ownership (e.g. cloud provider, VPN)
- Exclude trusted locations and known corporate VPNs
- Determine whether the activity represents a true incident or a false positive

If the activity is suspected as malicious, the alert is escalated to an incident and progresses to the Containment, Eradication, and Recovery phase.

Investigate the flagged account using the query below

```
let TargetUserPrincipalName = "98eb2485ddba6ef3439ed62d7f0274ac9fc34c21a71651b795dd69a1efdd64c3@lognpacific.com"; 
let TimePeriodThreshold = timespan(3d); 
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

Results: 

![image alt](https://github.com/Muts256/SNC-Public/blob/d3658edbf27af6e52e94d95f999b99bde2a02a76/Images/Incident-Response/Possible-Impossible-Travel/Im3.png)

From the logs, the user logged in from a location in New York. A minute later, the same user logged in from California.

Check what other activity the user was involved in 

```
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "e1102e6d-f8e4-447e-b177-e2692a7891ee"
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/13796b7f966d8dd8cb09b50512a2f96573fd8add/Images/Incident-Response/Possible-Impossible-Travel/Im5.png)

From the result, It does not look like there was anything malicious done by the user.


[Back to the Top](#table-of-contents)

---

## Containment, Eradication, and Recovery

**Containment actions include:**
- Temporarily disabling or restricting the affected user account
- Revoking active sign-in sessions and tokens
- Blocking suspicious IP addresses or ASNs where appropriate
- Enforcing step-up authentication or conditional access controls

**Eradication actions include:**
- Resetting the affected user’s credentials
- Forcing MFA re-registration if required
- Reviewing and correcting Conditional Access policy gaps
- Removing unauthorised devices or applications linked to the account

**Recovery actions include:**
- Re-enabling the user account once secured
- Validating successful authentication from trusted locations
- Monitoring the account for further anomalous sign-in activity
- Confirming normal business access is restored securely

The objective of this phase is to eliminate unauthorised access while minimising disruption to business operations.

Depending on the company policy and the evidence collected, there might be a need to isolate the device or disable the user account

Change the user's password. Remove any threat, ie, malware, if any was installed on the device


[Back to the Top](#table-of-contents)

---

# Post Incident Activity
Following the resolution of the **Impossible Travel** incident, a post-incident review is conducted to improve future detection and response capabilities.

Key activities include:

- Conducting a lessons-learned review with SOC and identity teams
- Analysing how the credentials were compromised (e.g. phishing, token replay)
- Reviewing the effectiveness of detection rules and alert timing
- Tuning Impossible Travel thresholds and time windows if required
- Updating exclusion lists for trusted locations and corporate VPNs
- Improving Conditional Access and MFA enforcement policies
- Enhancing monitoring for identity-based attacks
- Updating incident response playbooks and documentation
- Reporting findings and recommendations to stakeholders

The objective of this phase is continuous improvement, reducing the likelihood and impact of future identity compromise incidents.

Ensure to document all the steps taken. Put the notes into the activity log of the incident, and close the incident

---

## Lessons Learned

This lab highlighted several key lessons related to identity-based incident detection and response:

- **Detection tuning is critical:** Short detection windows (15–60 minutes)
  produced higher-confidence Impossible Travel alerts, while longer windows
  increased false positives.
- **Context improves accuracy:** MFA status, device information, and IP
  reputation were essential for validating alerts. Location data alone is
  insufficient.
- **Identity attacks are fast-moving:** Credential compromise can occur without
  malware, making rapid detection and containment of user accounts critical.
- **Exclusions require maintenance:** Trusted locations and corporate VPN
  exclusions must be reviewed regularly to avoid noise or blind spots.
- **Playbooks improve response:** Predefined response actions reduced time to
  containment and ensured consistent handling of incidents.

[Back to the Top](#table-of-contents)
