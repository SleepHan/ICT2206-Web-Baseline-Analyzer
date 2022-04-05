import os
import re
import subprocess
import sys


'''
Section 10: Request Limits
'''
def section10(apacheConfFile, apacheConfContent):
    print("### Start of Section 10 ###\n")
    search_reg_exp = [r"^512$", r"^100$", r"^1024$", r"^102400$"]
    expected_values = ["512", "100", "1024", "102400"]
    directive_lines = ["LimitRequestLine 512", "LimitRequestFields 100", "LimitRequestFieldSize 1024",
                       "LimitRequestBody 102400"]
    directives = ["LimitRequestLine", "LimitRequestFields", "LimitRequestFieldSize", "LimitRequestBody"]
    found = [False, False, False, False]
    changed = [False, False, False, False]

    apacheConfSplit = apacheConfContent.split('\n')

    for index in range(len(apacheConfSplit)):
        for i in range(0, 4):
            # If directive is in current line
            if directives[i] in apacheConfSplit[index]:
                limit_req_line = apacheConfSplit[index].split()
                original_value = limit_req_line[1]

                # Don't change the original value if it's correct.
                if re.match(search_reg_exp[i], original_value):
                    found[i] = True
                    print(directives[i] + " already has a value of " + expected_values[i])

                # Change the original value if it's incorrect.
                else:
                    changed[i] = True
                    print("Changed line: " + apacheConfSplit[index].rstrip() + " --> " +
                            directive_lines[i])  # Print all changed lines.
                    apacheConfSplit[index] = (directive_lines[i] + " # Corrected value from " + original_value + " to " +
                                                expected_values[i])  # Write the correct directive line.

    apacheConfSplit.append("\n### Start of Added Directives for Section 10  of CIS Benchmark ###\n")
    for j, found_bool in enumerate(found):
        if not found_bool and not changed[j]:
            # If directive doesn't exist in config, write to last line of new config
            apacheConfSplit.append(directive_lines[j])
            print("Added line: " + directive_lines[j])  # Print all added lines.
    apacheConfSplit.append("\n### End of Added Directives for Section 10  of CIS Benchmark ###")
    apacheConfContent = '\n'.join(apacheConfSplit)
    
    print("\n### End of Section 10 ###")
    return apacheConfContent


'''
Section 11: Enable SELinux to Restrict Apache Processes
'''
def section11(remedy):
    print("### Start of Section 11 ###\n")

    selinux_permissive = False
    selinux_enforcing = False
    selinux_installed = False

    ## 11.1 Ensure SELinux Is Enabled in Enforcing Mode.
    ret = subprocess.run("getenforce", capture_output=True, shell=True)
    getenforce_output = ret.stdout.decode()

    if "Disabled" in getenforce_output:
        selinux_installed = True

        if not remedy:
            print("SELinux is disabled. Please enable it with \'selinux-activate\' and a reboot.")
        else:  # Activate SELinux if installed but disabled.
            subprocess.run("selinux-activate", shell=True) # Activate SELinux (set to permissive), subject to a reboot.
            print("After reboot, run \'setenforce 1' to temporarily set SELinux to enforcing. Note that this can cause stability issues in Ubuntu.")
            print("Be warned that running \'selinux-config-enforcing\' will cause Ubuntu to hang on the next reboot\n")  

    elif "Permissive" in getenforce_output:
        selinux_installed = True
        selinux_permissive = True
        if not remedy:
            print("SELinux is enabled in Permissive mode. Enforce it with \'setenforce 1\', but at your own risk, because it can cause stability issues in Ubuntu.")
            

    elif "Enforcing" in getenforce_output:
        selinux_installed = True
        selinux_enforcing = True
        print("SELinux is enabled in Enforcing mode. No action is required.")
 
         
    # Enable SELinux if disabled or install SELinux if not installed, but only if AppArmor is not running.
    if remedy:
        apparmor_status = os.system("systemctl is-active --quiet apparmor >/dev/null 2>&1")

        # If AppArmor is running, don't install SELinux.
        if apparmor_status == 0: 
            print("AppArmor is running. Skipping Section 11...")
        


        # Install and activate SELinux if not installed.
        if not selinux_installed:
            install_selinux = ""
            while not install_selinux == "y" and not install_selinux == "n":
                install_selinux = input("Install SELinux? (Y/N) ").rstrip().lower()
                if install_selinux == "y":
                    print("Installing SELinux...\n")
                    subprocess.run("apt-get install selinux-basics selinux-utils policycoreutils -y >/dev/null 2>&1", shell=True)
                    subprocess.run("selinux-activate", shell=True) # Activate SELinux (set to permissive), subject to a reboot.
                    selinux_installed = True
                    print("After reboot, run \'setenforce 1' to temporarily set SELinux to enforcing. Note that this can cause stability issues in Ubuntu.")
                    print("Be warned that running \'selinux-config-enforcing\' will cause Ubuntu to hang on the next reboot\n")

                elif install_selinux == "n" :
                    print("SELinux will not be installed.\n")
                    
                else:
                    continue
        
        # Prompts user to set SELinux to enforcing if mode is permissive, at least until the next reboot.
        if selinux_permissive:
            enforce_selinux = ""
            while not enforce_selinux == "y" and not enforce_selinux == "n":
                enforce_selinux = input("Set SELinux to enforcing? Note that this can cause stability issues in Ubuntu.(Y/N) ").rstrip().lower()
                if enforce_selinux == "y":
                    subprocess.run("setenforce 1", shell=True)
                    print("SELinux set to enforcing.")
                    selinux_enforcing = True

                elif enforce_selinux == "n":
                    print("SELinux will not be set to enforcing.\n")
                    
                else:
                    continue


    # If SELinux is not installed, exit Section 11 since the rest of the section will involve SELinux.
    if not selinux_installed:
        print("SELinux is not installed. If you wish to install SELinux, ensure that AppArmor is not installed and run this command: \'apt-get install selinux-basics selinux-utils policycoreutils -y\'.")
        print("However, it is recommended to install AppArmor instead of SELinux, because the latter can cause stability issues in Ubuntu.")
        print("\n### End of Section 11 ###")
        return

    if selinux_enforcing or selinux_permissive:
        ## 11.2 Ensure Apache Processes Run in the httpd_t Confined Context 
        ret = subprocess.run("ps -eZ | grep httpd_t", capture_output=True, shell=True)
        ps_httpd_t_output = ret.stdout.decode()
        if "httpd_t" and "apache2" in ps_httpd_t_output:
            print("Apache is running in the httpd_t confined context. No action is required.")
        else:
            print("Apache2 not running in httpd_t confined context. Refer to CIS Benchmark 11.2 for manual remidiation.")

            if remedy:
                subprocess.run("chcon -t initrc_exec_t /usr/sbin/apachectl", shell=True)
                subprocess.run("chcon -t httpd_exec_t /usr/sbin/apache2 /usr/sbin/apache2.*", shell=True)
                subprocess.run("semanage fcontext -f f -a -t initrc_exec_t /usr/sbin/apachectl", shell=True)
                subprocess.run("semanage fcontext -f f -a -t httpd_exec_t /usr/sbin/apache2", shell=True)
                subprocess.run("restorecon -v /usr/sbin/apache2 /usr/sbin/apachectl", shell=True) 

        ## 11.3 Ensure the httpd_t Type is Not in Permissive Mode
        ret = subprocess.run("semodule -l | grep permissive_httpd_t", capture_output=True, shell=True)
        httpd_t_type_output = ret.stdout.decode()
        if "permissive" in httpd_t_type_output:
            print("httpd_t Type is in Permissive Mode. Please disable it.")
            if remedy:
                subprocess.run("semanage permissive -d httpd_t", shell=True)
        else:
            print("httpd_Type is not in Permissive Mode. No action is required.")

        ## 11.4 Ensure Only the Necessary SELinux Booleans are Enabled
        ret = subprocess.run("getsebool -a | grep httpd_ | grep '> on'", capture_output=True, shell=True)
        httpd_booleans = ret.stdout.decode()

        # If there are enabled SELinux httpd booleans present, print them, and remediate them if necessary.
        if len(httpd_booleans)!=0:
            print("\nList of enabled SELinux httpd booleans:\n")
            
            for httpd_boolean in httpd_booleans.split('\n'):
                if len(httpd_boolean) !=0:
                    print("--> " + httpd_boolean.replace(" --> on", ""))

            print("\nDisable httpd booleans which are unnecessary with the command \'setsebool -P <httpd boolean>\'.")
            if remedy:
                httpd_booleans_to_disable = input("Enter SELinux httpd booleans to disable (separated by comma): ")

                httpd_booleans_to_disable_list = httpd_booleans_to_disable.split(",")
                
                print("SELinux httpd booleans to disable: \n")
                for httpd_boolean in httpd_booleans_to_disable_list:
                    httpd_boolean = httpd_boolean.strip().replace("\n", "")
                    ret = subprocess.run("setsebool -P " + httpd_boolean + " off", capture_output=True, shell=True)
                    setsebool_output = ret.stdout.decode()
                    print(setsebool_output)
                    if "not defined" in setsebool_output: # If httpd_boolean entered is invalid.
                        print("Invalid boolean " + httpd_boolean + " identified.")
                        print("Enter the command \'setsebool -P <httpd boolean>\' manually to try again.")
                    else: # If httpd_boolean is valid, disable it.
                        print(httpd_boolean + " disabled.")

        # If there are no SELinux httpd booleans, do nothing.
        else: 
            print("No SELinux httpd booleans found. No action is required.")

    print("\n### End of Section 11 ###")


'''
Section 12: Enable AppArmor to Restrict Apache Processes. 
'''
def section12(remedy):
    print("### Start of Section 12 ###\n")

    apparmor_apache2_config_file = "/etc/apparmor.d/usr.sbin.apache2"
    selinux_installed = False
    apparmor_installed = False

    ## 12.1  Ensure the AppArmor Framework Is Enabled
    ret = subprocess.run("getenforce", capture_output=True, shell=True)
    getenforce_error_code = ret.returncode

    if getenforce_error_code==0:
        print("SELinux is installed. Skipping Section 12...")
        selinux_installed = True

    # Proceed only if SELinux is disabled or not installed.
    if not selinux_installed:
        ret = subprocess.run("aa-status --enabled && echo Enabled", capture_output=True, shell=True)
        apparmor_status_output = ret.stdout.decode()
        # If AppArmor is not enabled/not installed and remedy option is enabled, prompt user to install AppArmor.
        if not "Enabled" in apparmor_status_output and remedy:
            print("SELinux is not installed. Proceeding with AppArmor installation...")
            install_apparmor = ""
            while not install_apparmor == "y" and not install_apparmor == "n":
                install_apparmor = input("AppArmor not installed. Install it? (Y/N) ").rstrip().lower()
                if install_apparmor == "y":
                    print("Installing AppArmor...")
                    subprocess.run("apt-get update >/dev/null 2>&1 && apt-get install apparmor libapache2-mod-apparmor apparmor-utils snapd -y >/dev/null 2>&1", shell=True)
                    subprocess.run("/etc/init.d/apparmor start", shell=True) 
                    apparmor_installed = True

                elif install_apparmor == "n":
                    print("AppArmor will not be installed.\n")
                else:
                    continue

        # If AppArmor is not enabled/not installed and remedy option is not enabled, tell user to install AppArmor.
        elif not "Enabled" in apparmor_status_output and not remedy:
            print("AppArmor is not installed. If you wish to install AppArmor, ensure that SELinux is not installed, and run this command: \'apt-get install apparmor libapache2-mod-apparmor apparmor-utils snapd -y\'.")
            print("\n### End of Section 12 ###")
            return

        # If AppArmor is already enabled/installed, run checks on the Apache AppArmor Profile config file.
        else:
            apparmor_installed = True
            print("Checking if AppArmor is running....")
            apparmor_status = os.system("systemctl is-active --quiet apparmor")

            if apparmor_status!=0:
                print("AppArmor not started.")
                subprocess.run("/etc/init.d/apparmor start", shell=True)
            else:
                print("AppArmor is already running.")
                apparmor_apache2_config_file_download_link = "\"https://raw.githubusercontent.com/gentoo/gentoo-apparmor-profiles/master/usr.sbin.apache2\""    
                if not os.path.exists(apparmor_apache2_config_file): # If AppArmor Apache2 config file is not found, install AppArmor dependencies
                    download_apparmor_apache2_config_file = ""
                    while not download_apparmor_apache2_config_file == "y" and not download_apparmor_apache2_config_file == "n":
                        download_apparmor_apache2_config_file = input("AppArmor config file not found (required for audit). Download it? (Y/N) ").rstrip().lower()
                        if download_apparmor_apache2_config_file == "y":
                            print("Downloading " + apparmor_apache2_config_file + "...")
                            subprocess.run("wget " + apparmor_apache2_config_file_download_link + " -O \"/etc/apparmor.d/usr.sbin.apache2\" >/dev/null 2>&1", shell=True)
                            subprocess.run("/etc/init.d/apparmor reload", shell=True)

                        elif download_apparmor_apache2_config_file == "n":
                            print("Default AppArmor Apache configuration file downloaded.\n")
                        else:
                            continue

        # Proceed only if AppArmor is enabled/installed.
        if apparmor_installed:
            ## 12.2 Ensure the Apache AppArmor Profile Is Configured Properly.
            capablities = ["capability dac_override", "capability dac_read_search", "capability net_bind_service", "capability setgid", "capability setuid", "capability kill", "capability sys_tty_config"]
            capablities_found = []
            
            permissions = ["/usr/sbin/apache2 mr", "/etc/gai.conf r", "/etc/group r", "/etc/apache2/** r", "/var/www/html/** r", "/run/apache2/** rw", "/run/lock/apache2/** rw", "/var/log/apache2/** rw", "/etc/mime.types r"]
            permissions_found = []
            
            forbidden_lines = []

            try:
                with open(apparmor_apache2_config_file, "r") as f:
                    apparmor_apache2_config = f.readlines()
                    for line in apparmor_apache2_config:
                        line = line.lstrip()
                        if "#" in line:
                            continue
                        elif re.match(r"^/\*\*", line):
                            forbidden_lines.append(line.replace(",","").rstrip())
                            permissions_found.append(line.replace(",","").rstrip())  

                        elif re.match(r"^/ r[wx]", line):
                            forbidden_lines.append(line.replace(",","").rstrip())
                            permissions_found.append(line.replace(",","").rstrip())
                        
                        elif "capability" in line:
                            capablities_found.append(line.replace(",","").rstrip())

                        elif re.match(r"^/.*[mrwlkix]$", line.replace(',',"").rstrip()): # Find line containing permissions. First char must be "/" and last char must be either "m", "w", "r", or "x".
                            permissions_found.append(line.replace(",",""))  
            except FileNotFoundError:
                print(apparmor_apache2_config_file + " not found!")

            print("\nCapabilities found:\n") 
            if len(capablities_found) == 0:
                print("None\n")
            for capability_found in list(set(capablities_found)):
                print("--> " + capability_found)

            print("\nRecommended Capabilities:\n") 
            for capability in capablities:
                print("--> " + capability) 

            print("\nPermissions found:\n") 
            
            if len(permissions_found) == 0:
                print("None\n")
            for permission_found in list(set(permissions_found)):
                print("--> " + permission_found)       

            print("\nRecommended Permissions:\n") 
            for permission in permissions:
                print("--> " + permission) 

            print("\nForbidden Lines (remove them):\n")  
            for forbidden_line in list(set(forbidden_lines)):
                print("--> " + forbidden_line) 
            
            
            ## Section 12.3 Ensure Apache AppArmor Profile is in Enforce Mode.

            print("\nChecking if Apache AppArmor Profile is in Enforce Mode...")
            
            check_if_apparmor_enforced = "aa-unconfined --paranoid | grep apache2"
            ret = subprocess.run(check_if_apparmor_enforced, capture_output=True, shell=True)
            check_if_apparmor_enforced_output = ret.stdout.decode()

            if "confined by" and "(enforce)" in check_if_apparmor_enforced_output:
                print("Apache AppArmor Profile is in Enforce Mode. No action is required.")
            else:
                print("Apache AppArmor Profile is not in Enforce Mode. Enforce it by running the command \'aa-enforce apache\'.")

            # If remedy option is enabled, implement the recommended state for both Section 12.2 and Section 12.3.
            if remedy:
                subprocess.run("service apache2 stop >/dev/null 2>&1", shell=True)
                subprocess.run("aa-autodep apache2", shell=True)
                subprocess.run("aa-complain apache2", shell=True)
                subprocess.run("service apache2 start >/dev/null 2>&1", shell=True)
                subprocess.run("aa-logprof", shell=True)
                subprocess.run("apparmor_parser -r /etc/apparmor.d/usr.sbin.apache2", shell=True)
                subprocess.run("aa-enforce apache2", shell=True)
                subprocess.run("/etc/init.d/apparmor reload", shell=True)
    
    print("\n### End of Section 12 ###")