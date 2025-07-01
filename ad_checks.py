import re
import os
import ldap3
import datetime
from ldap3 import Server, Connection, ALL, SUBTREE
import argparse
import subprocess
import winreg
import configparser
import json
import win32evtlog
import xml.etree.ElementTree as ET

# Function to check for common AD misconfigurations
def check_ad_misconfigurations(server_url, username, password):
    try:
        # Connect to the LDAP server
        server = Server(server_url, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        print("[+] Successfully connected to the Active Directory server.")

        # Perform checks
        
        # 1. Detect Unconstrained Delegation
        print("\n[Check 1] Detecting accounts with Unconstrained Delegation...")
        conn.search(
            search_base=server.info.other['defaultNamingContext'][0],
            search_filter='(&(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            search_scope=SUBTREE,
            attributes=['sAMAccountName']
        )
        if conn.entries:
            print("[!] Accounts with Unconstrained Delegation:")
            for entry in conn.entries:
                print(f"  - {entry['sAMAccountName']}")
        else:
            print("[+] No accounts with Unconstrained Delegation found.")

        # 2. Check for Weak Password Policies
        print("\n[Check 2] Checking for weak password policies...")
        conn.search(
            search_base=server.info.other['defaultNamingContext'][0],
            search_filter='(objectClass=domainDNS)',
            attributes=['minPwdLength', 'pwdHistoryLength', 'maxPwdAge']
        )
        if conn.entries:
            domain_info = conn.entries[0]
            try:
                # Extracting values
                min_pwd_length = int(domain_info['minPwdLength'].value)
                pwd_history_length = int(domain_info['pwdHistoryLength'].value)

                # Handling maxPwdAge (convert to days)
                max_pwd_age = domain_info['maxPwdAge'].value
                if isinstance(max_pwd_age, datetime.timedelta):
                    max_pwd_age_days = abs(max_pwd_age.days)  # Convert to positive days
                else:
                    max_pwd_age_days = int(max_pwd_age)

                # Print password policy details
                print(f"  Minimum Password Length: {min_pwd_length}")
                print(f"  Password History Length: {pwd_history_length}")
                print(f"  Maximum Password Age (in days): {max_pwd_age_days}")

                # Check password policy strength
                if min_pwd_length < 12:
                    print("[!] Minimum password length is less than 12 characters. Consider increasing it.")
                else:
                    print("[+] Password length policy looks strong.")
            except Exception as e:
                print(f"[!] Error processing password policy attributes: {e}")
        else:
            print("[!] No domain policy attributes found.")

        
        # 3. Check for Anonymous LDAP Binds
        print("\n[Check 3] Checking for anonymous LDAP binds...")
        anonymous_conn = Connection(server, auto_bind=True)
        if anonymous_conn.bind():
            print("[!] Anonymous LDAP binding is allowed. This is a security risk.")
        else:
            print("[+] Anonymous LDAP binding is disabled.")

        # 4. Enumerate Privileged Groups
        print("\n[Check 4] Enumerating privileged groups...")
        privileged_groups = [
            'Domain Admins', 'Enterprise Admins', 'Administrators',
            'Schema Admins', 'Backup Operators'
        ]
        for group in privileged_groups:
            conn.search(
                search_base=server.info.other['defaultNamingContext'][0],
                search_filter=f'(&(objectClass=group)(cn={group}))',
                attributes=['member']
            )
            if conn.entries:
                print(f"[!] Members of {group}:")
                for member in conn.entries[0]['member']:
                    print(f"  - {member}")
            else:
                print(f"[+] No members found in {group}.")

        # 5. Check for Expired or Inactive Accounts
        print("\n[Check 5] Detecting expired or inactive accounts...")
        conn.search(
            search_base=server.info.other['defaultNamingContext'][0],
            search_filter='(&(objectClass=user)(|(accountExpires<=0)(!(lastLogonTimestamp>=0))))',
            attributes=['sAMAccountName', 'accountExpires', 'lastLogonTimestamp']
        )
        if conn.entries:
            print("[!] Expired or inactive accounts:")
            for entry in conn.entries:
                print(f"  - {entry['sAMAccountName']} (Last Logon: {entry['lastLogonTimestamp']})")
        else:
            print("[+] No expired or inactive accounts found.")

        # 6. Check for LLMNR Poisoning Risk
        print("\n[Check 6] Checking for LLMNR status via Group Policy...")
        try:
            # Use PowerShell to query the registry key for LLMNR
            result = subprocess.run(
                ['powershell', '-Command',
                r"Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                output = result.stdout.strip()
                if "EnableMulticast" in output:
                    # Parse the value of EnableMulticast
                    for line in output.splitlines():
                        if "EnableMulticast" in line:
                            value = line.split(":")[1].strip()
                            if value == "0":
                                print("[+] LLMNR is disabled (via Group Policy).")
                            elif value == "1":
                                print("[!] LLMNR is enabled (via Group Policy).")
                            else:
                                print(f"[!] Unexpected value for EnableMulticast: {value}")
                            break
                else:
                    print("[!] LLMNR is not configured via Group Policy.")
            else:
                if "Cannot find path" in result.stderr:
                    print("[!] LLMNR is not configured via Group Policy.")
                else:
                    print("[!] LLMNR registry key not found. LLMNR is likely enabled by default.")
        except Exception as e:
            print(f"[!] Error checking LLMNR status via Group Policy: {e}")


        # 7. Check for SMB Signing Enforcement
        print("\n[Check 7] Checking if SMB signing is enforced...")
        try:
            # Run PowerShell command to get SMB configuration
            result = subprocess.run(
                ['powershell', '-Command', "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                print("[+] SMB Configuration Retrieved:")
                print(output)

                # Extract lines from output
                lines = output.splitlines()

                # Ensure there are enough lines
                if len(lines) >= 3:
                    # Extract the third line containing the values
                    values_line = lines[2]

                    # Split the line into values (assuming space-based separation)
                    values = values_line.split()

                    # Extract the values of RequireSecuritySignature and EnableSecuritySignature
                    if len(values) >= 2:
                        require_signature = values[0].strip() == 'True'
                        enable_signature = values[1].strip() == 'True'

                        # Evaluate the enforcement status
                        if require_signature and enable_signature:
                            print("[+] SMB signing is enforced for the account. This mitigates SMB relay attacks.")
                        else:
                            print("[!] SMB signing is not fully enforced. This may leave the system vulnerable to SMB relay attacks.")
                            if not require_signature:
                                print("[!] RequireSecuritySignature is not set to True.")
                            if not enable_signature:
                                print("[!] EnableSecuritySignature is not set to True.")
                    else:
                        print("[!] Unexpected number of values in SMB configuration output.")
                else:
                    print("[!] SMB configuration output format is unexpected.")
            else:
                print(f"[!] Failed to retrieve SMB configuration. Error: {result.stderr.strip()}")
        except Exception as e:
            print(f"[!] Error while checking SMB signing enforcement: {e}")

        # 8. Check for AS-REP Roasting Vulnerabilities
        print("\n[Check 8] Checking for AS-REP roasting vulnerabilities...")
        try:
            conn.search(
                search_base=server.info.other['defaultNamingContext'][0],
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                attributes=['sAMAccountName', 'distinguishedName']
            )
            if conn.entries:
                print("[!] Accounts vulnerable to AS-REP roasting:")
                for entry in conn.entries:
                    print(f"  - Username: {entry['sAMAccountName']}, DN: {entry['distinguishedName']}")
            else:
                print("[+] No accounts vulnerable to AS-REP roasting found.")
        except Exception as e:
            print(f"[!] Error while checking for AS-REP roasting vulnerabilities: {e}")

        # 9. Identify Accounts with Service Principal Names (SPNs)
        print("\n[Check 9] Identifying service accounts with SPNs (Kerberoasting vulnerabilities)...")

        try:
            # Search for accounts with SPNs
            conn.search(
                search_base=server.info.other['defaultNamingContext'][0],
                search_filter="(servicePrincipalName=*)",
                attributes=["sAMAccountName", "servicePrincipalName", "pwdLastSet"]
            )
            if conn.entries:
                print(f"  Found {len(conn.entries)} accounts with SPNs:")
                for entry in conn.entries:
                    account_name = entry['sAMAccountName']
                    spn = entry['servicePrincipalName']
                    pwd_last_set = entry['pwdLastSet']
                    print(f"    - Account: {account_name}, SPN: {spn}, Password Last Set: {pwd_last_set}")
                    print("      [!] Review password policy and ensure strong passwords are enforced.")
            else:
                print("[+] No accounts with SPNs found.")
        except Exception as e:
            print(f"[!] Error while checking for Kerberoasting vulnerabilities: {e}")

        # 10. AdminSDHolder Protection Review
        print("\n[Check 11] Reviewing AdminSDHolder protection...")

        try:
            # Search for AdminSDHolder object
            conn.search(
                search_base='CN=AdminSDHolder,CN=System,' + server.info.other['defaultNamingContext'][0],
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor']
            )
            
            if conn.entries:
                print("[+] Retrieved AdminSDHolder object.")
                
                # Fetch and analyze ACL
                acl = conn.entries[0]['nTSecurityDescriptor']
                authorized_accounts = [
                    'S-1-5-32-544',  # Administrators group
                    'S-1-5-9',       # Enterprise Domain Controllers
                    'S-1-5-21-*-512' # Domain Admins (specific SID depends on the domain)
                ]
                
                unauthorized_accounts = []
                for ace in acl:
                    if ace['Trustee'] not in authorized_accounts:
                        unauthorized_accounts.append(ace['Trustee'])
                
                if unauthorized_accounts:
                    print("[!] Unauthorized accounts found on AdminSDHolder ACL:")
                    for account in unauthorized_accounts:
                        print(f"  - {account}")
                else:
                    print("[+] AdminSDHolder ACL contains only authorized permissions.")
            else:
                print("[!] Could not locate AdminSDHolder object in the directory.")
        except Exception as e:
            print(f"[!] Error while reviewing AdminSDHolder protection: {e}")


        # 11. Group Managed Service Account (gMSA) Utilization
        print("\n[Check 11] Group Managed Service Account (gMSA) Utilization...")
        conn.search(
            search_base=server.info.other['defaultNamingContext'][0],
            search_filter='(&(objectClass=msDS-GroupManagedServiceAccount))',
            attributes=['sAMAccountName']
        )
        if conn.entries:
            print("[!] gMSA accounts identified:")
            for entry in conn.entries:
                print(f"  - {entry['sAMAccountName']}")
        else:
            print("[+] No gMSA accounts found.")

        
        # 12. Account Lockout Policy Configuration
        print("\n[Check 12] Reviewing Account Lockout Policy Configuration...")

        try:
            # PowerShell command to retrieve the account lockout settings
            command = [
                "powershell",
                "-Command",
                "Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutDuration, LockoutThreshold, LockoutObservationWindow"
            ]
            
            # Execute the command
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout.strip()

            if result.returncode == 0 and output:
                print("[+] Retrieved account lockout policy:")
                # Parse the output
                lines = output.splitlines()
                
                # Ensure data starts after header (second line onwards)
                if len(lines) > 2:
                    policy_data = lines[2].split()
                    if len(policy_data) == 3:
                        lockout_duration = policy_data[0]  # e.g., "00:30:00"
                        lockout_threshold = policy_data[1]  # e.g., "5"
                        lockout_observation_window = policy_data[2]  # e.g., "00:30:00"

                        # Display the settings
                        print(f"    Lockout Duration: {lockout_duration}")
                        print(f"    Lockout Threshold: {lockout_threshold} invalid login attempts")
                        print(f"    Observation Window: {lockout_observation_window}")
                        
                        # Add policy validation logic if needed
                        if lockout_threshold == "0":
                            print("[!] Lockout Threshold is disabled (0 invalid attempts). Consider enabling it.")
                        else:
                            print("[+] Lockout policy is configured.")
                    else:
                        print("[!] Unexpected data format in policy output.")
                else:
                    print("[!] No policy data retrieved. Ensure the command is run in a domain environment.")
            else:
                print("[!] Error retrieving account lockout policy settings.")
                print(result.stderr)

        except Exception as e:
            print(f"[!] An error occurred while checking account lockout policy: {str(e)}")


        # 13. NTLM Authentication Usage Analysis -- Needs to be checked
        print("\n[Check 13] NTLM Authentication Usage Analysis...")

        server = 'localhost'
        log_type = 'Security'

        # Open the Security Event Log
        try:
            handle = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)

            ntlm_events = []
            for event in events:
                # Check for NTLM-related Event IDs
                if event.EventID in [4624, 4776]:
                    if "NTLM" in str(event.StringInserts):
                        ntlm_events.append({
                            "EventID": event.EventID,
                            "TimeGenerated": event.TimeGenerated,
                            "Source": event.SourceName,
                            "Details": event.StringInserts
                        })

            win32evtlog.CloseEventLog(handle)

            # Display NTLM events if found
            if ntlm_events:
                print(f"[!] NTLM authentication detected! Total Events: {len(ntlm_events)}")
                for evt in ntlm_events:
                    print(f"[!] EventID: {evt['EventID']}, Time: {evt['TimeGenerated']}, Details: {evt['Details']}")
            else:
                print("[+] No NTLM authentication events found.")
        except Exception as e:
            print(f"Error while checking NTLM usage: {e}")


        # 14. LAN Manager Authentication Level
        print("\n[Check 14] LAN Manager Authentication Level...")
        try:
        # Open registry key
            reg_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ) as key:
                # Get the LmCompatibilityLevel value
                lm_compatibility_level, reg_type = winreg.QueryValueEx(key, "LmCompatibilityLevel")

            # Interpret and print the result
            recommended_level = 5
            if lm_compatibility_level == recommended_level:
                print(f"[+] LAN Manager Authentication Level is correctly set to {lm_compatibility_level}.")
            else:
                print(f"[!] Warning: LAN Manager Authentication Level is set to {lm_compatibility_level}. Recommended value: {recommended_level}.")
        except FileNotFoundError:
            print("[!] LmCompatibilityLevel setting not found in the registry. Default value (0) may be applied.")
        except Exception as e:
            print(f"Error while checking LAN Manager Authentication Level: {e}")


        # Check 15: Kerberos Maximum Ticket Age Configuration
        print("\n[Check 15] Assessing the Maximum Kerberos Ticket Lifetime...")
        try:
            # Generate a GPO report in XML format for the "Default Domain Policy"
            powershell_command = (
                'Get-GPOReport -Name "Default Domain Policy" -ReportType XML -Path "C:\\KerberosPolicy.xml"'
            )

            result = subprocess.run(
                ["powershell", "-Command", powershell_command],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("[!] Error generating GPO report using PowerShell.")
                print(result.stderr.strip())
                return

            # Load the GPO XML file
            xml_file_path = "C:\\KerberosPolicy.xml"
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Define the namespace to handle "q1" tags
            namespace = {"q1": "http://www.microsoft.com/GroupPolicy/Settings/Security"}

            # Extract Kerberos settings using XPath
            max_service_age = root.find(".//q1:Account[q1:Name='MaxServiceAge']/q1:SettingNumber", namespace)
            max_ticket_age = root.find(".//q1:Account[q1:Name='MaxTicketAge']/q1:SettingNumber", namespace)
            max_renew_age = root.find(".//q1:Account[q1:Name='MaxRenewAge']/q1:SettingNumber", namespace)

            # Retrieve the values or set default to "Not Defined"
            service_ticket = max_service_age.text if max_service_age is not None else "Not Defined"
            user_ticket = max_ticket_age.text if max_ticket_age is not None else "Not Defined"
            ticket_renewal = max_renew_age.text if max_renew_age is not None else "Not Defined"

            # Display the settings
            print(f"  Maximum lifetime for service ticket: {service_ticket} minutes")
            print(f"  Maximum lifetime for user ticket: {user_ticket} hours")
            print(f"  Maximum lifetime for ticket renewal: {ticket_renewal} days")

            # Recommendations based on retrieved values
            if "Not Defined" in [service_ticket, user_ticket, ticket_renewal]:
                print("[!] Some Kerberos ticket lifetime settings are not defined.")
            else:
                print("[+] Kerberos ticket lifetime settings retrieved successfully.")

        except Exception as e:
            print(f"[!] Error while assessing Kerberos ticket settings: {e}")


        # 16. Check 16 Domain and Forest Functional Level Assessment
        print("\n[Check 16] Assessing Domain and Forest Functional Levels...")
        try:
            # PowerShell command to fetch functional levels
            ps_script = """
            $forestLevel = (Get-ADForest).ForestMode
            $domainLevel = (Get-ADDomain).DomainMode
            @{"DomainFunctionalLevel" = $domainLevel; "ForestFunctionalLevel" = $forestLevel} | ConvertTo-Json -Compress
            """
            
            # Execute PowerShell script
            result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)
            
            # Debug output
            print(f"[DEBUG] Raw PowerShell Output: {result.stdout.strip()}")

            if result.returncode != 0:
                print(f"[!] PowerShell Execution Error: {result.stderr.strip()}")
            else:
                # Parse PowerShell JSON output
                data = json.loads(result.stdout.strip())

                domain_functional_level = data.get("DomainFunctionalLevel", "Unknown")
                forest_functional_level = data.get("ForestFunctionalLevel", "Unknown")

                print(f"[+] Domain Functional Level: {domain_functional_level}")
                print(f"[+] Forest Functional Level: {forest_functional_level}")

                # Mapping functional levels to numeric values
                level_mapping = {
                    "Windows2000Domain": 0,
                    "Windows2003Domain": 2,
                    "Windows2008Domain": 3,
                    "Windows2008R2Domain": 4,
                    "Windows2012Domain": 5,
                    "Windows2012R2Domain": 6,
                    "Windows2016Domain": 7,
                    "Windows2019Domain": 8,
                    "Windows2022Domain": 9
                }

                # Convert to numeric for comparison
                domain_numeric = level_mapping.get(domain_functional_level, -1)
                forest_numeric = level_mapping.get(forest_functional_level, -1)

                recommended_level = 7  # Windows Server 2016 or later recommended

                if domain_numeric < recommended_level or forest_numeric < recommended_level:
                    print("[!] Consider upgrading the domain/forest functional level to leverage modern security features.")
                else:
                    print("[+] Functional levels are up to date.")

        except Exception as e:
            print(f"[!] Unexpected Error: {e}")
            

        # 17. Check 17: User Ticket Encryption Enforcement
        print("\n[Check 17] Verifying User Ticket Encryption Enforcement...")

        # Recommended encryption types: AES128, AES256
        recommended_encryption_types = ['AES128_HMAC_SHA1', 'AES256_HMAC_SHA1']

        try:
            # Step 1: Verify Group Policy Encryption Types
            gpo_command = r'(Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Kerberos\Parameters" -Name "SupportedEncryptionTypes").SupportedEncryptionTypes'
            gpo_result = subprocess.check_output(['powershell.exe', '-Command', gpo_command], text=True).strip()
            print(f"[DEBUG] GPO Encryption Types Value: {gpo_result}")
            
            # Interpretation of GPO Encryption Types
            gpo_encryption_types = int(gpo_result) if gpo_result.isdigit() else -1
            if gpo_encryption_types == -1:
                print("[!] GPO Encryption Types are not defined or not configured.")
            else:
                print(f"[+] GPO Encryption Types Value: {gpo_encryption_types}")

            # Step 2: Verify Active Directory Account Encryption Types
            ad_command = 'Get-ADUser -Filter {SamAccountName -eq "krbtgt"} -Properties msDS-SupportedEncryptionTypes | Select-Object -ExpandProperty msDS-SupportedEncryptionTypes'
            ad_result = subprocess.check_output(['powershell.exe', '-Command', ad_command], text=True).strip()
            print(f"[DEBUG] AD Account Encryption Types Value: {ad_result}")
            
            ad_encryption_types = int(ad_result) if ad_result.isdigit() else -1
            if ad_encryption_types == -1:
                print("[!] AD Account (krbtgt) Encryption Types are not defined or not configured.")
            else:
                print(f"[+] AD Account Encryption Types Value: {ad_encryption_types}")

            # Step 3: Compare and Recommend
            if gpo_encryption_types < 0 and ad_encryption_types < 0:
                print("[!] No encryption enforcement detected in both GPO and AD account settings.")
            else:
                if ad_encryption_types > 0 and gpo_encryption_types > 0:
                    if ad_encryption_types == gpo_encryption_types:
                        print("[+] Encryption types match between GPO and AD account settings.")
                    else:
                        print("[!] Mismatch between GPO and AD account encryption types. Review configuration.")
                else:
                    print("[!] Inconsistent encryption type configurations detected.")

        except Exception as e:
            print(f"[!] Unexpected Error: {e}")


        # 18. Check 18 DNS Security Assessment (DNSSEC)
        print("\n[Check 18] Evaluating DNS Security Configuration (DNSSEC)...")
        try:
            dns_command = ['powershell.exe', '-Command', 'Get-DnsServerZone | Select-Object ZoneName,IsSigned']
            dns_output = subprocess.check_output(dns_command, text=True)
            if dns_output:
                print("[+] DNSSEC Status:")
                print(dns_output)
                if "True" in dns_output:
                    print("[+] DNSSEC is implemented for at least one DNS zone.")
                else:
                    print("[!] DNSSEC is not implemented. Consider enabling DNSSEC to prevent DNS spoofing and cache poisoning.")
            else:
                print("[!] No DNS zones found or unable to retrieve DNSSEC status.")
        except Exception as e:
            print(f"[!] Error while evaluating DNSSEC status: {e}")

        
        # 19. Checking for accounts with DCSync replication privileges 
        print("\n[Check 19] Checking for accounts with effective DCSync replication privileges...")

        try:
            # Step 1: Get accounts with explicit replication ACEs on domain root
            powershell_script = r'''
            $domainDN = (Get-ADDomain).DistinguishedName
            $acl = Get-Acl "AD:$domainDN"
            $acl.Access | Where-Object {
                $_.ActiveDirectoryRights -match "ReplicatingDirectoryChanges" -or
                $_.ActiveDirectoryRights -match "ReplicatingDirectoryChangesAll" -or
                $_.ActiveDirectoryRights -match "ReplicatingDirectoryChangesInFilteredSet"
            } | Select-Object -Property IdentityReference, ActiveDirectoryRights
            '''

            result = subprocess.run(
                ['powershell.exe', '-Command', powershell_script],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("[!] Failed to retrieve DCSync ACEs:", result.stderr.strip())
            else:
                ace_output = result.stdout.strip()
                if ace_output:
                    print("[+] Explicit replication rights found:\n")
                    for line in ace_output.splitlines():
                        if "IdentityReference" in line or line.strip() == "":
                            continue
                        print("    - " + line.strip())
                else:
                    print("[+] No explicit ACEs for replication rights found.")

            # Step 2: Enumerate members of well-known DCSync-capable groups
            dcsync_groups = ["Domain Admins", "Enterprise Admins", "Administrators", "Backup Operators", "Account Operators"]
            all_members = []

            for group in dcsync_groups:
                ps_group_members = f'''
                Get-ADGroupMember -Identity "{group}" -Recursive | Select-Object -ExpandProperty SamAccountName
                '''
                result = subprocess.run(
                    ['powershell.exe', '-Command', ps_group_members],
                    capture_output=True,
                    text=True
                )
                members = result.stdout.strip().splitlines() if result.returncode == 0 else []
                if members:
                    print(f"\n[+] Members of '{group}' (inherited DCSync rights):")
                    for user in members:
                        print(f"    - {user}")
                        all_members.append(user)
                else:
                    print(f"\n[+] No members found in '{group}' or unable to retrieve.")

            if not ace_output and not all_members:
                print("\n[+] No accounts found with DCSync replication rights (explicit or inherited).")

            else:
                print("\n[!] Review these accounts carefully. They have effective DCSync capability and can extract credentials from Active Directory.")
        except Exception as e:
            print(f"[!] Error during DCSync rights evaluation: {e}")



        conn.unbind()

    except Exception as e:
        print(f"[!] Error: {e}")


# Main function
def main():
    parser = argparse.ArgumentParser(description="Active Directory Misconfiguration Checker")
    parser.add_argument('--server', required=True, help="LDAP server URL (e.g., ldap://example.com)")
    parser.add_argument('--username', required=True, help="Username for LDAP authentication")
    parser.add_argument('--password', required=True, help="Password for LDAP authentication")
    
    args = parser.parse_args()
    
    check_ad_misconfigurations(args.server, args.username, args.password)

if __name__ == "__main__":
    main()


#Usage - python ad_checks.py --server ldap://10.0.2.9 --username USER@MARVEL.local --password Password1