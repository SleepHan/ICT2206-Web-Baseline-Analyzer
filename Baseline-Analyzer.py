import os
import re
import subprocess
import section24, section_5_and_9, section6, section78, section1012
import argparse
import shutil
from argparse import RawTextHelpFormatter

'''
Will either run or print the command given based on the remedy flag
'''
def commandRun(command):
    if remedy:
        os.system('{} >/dev/null 2>&1'.format(command))
    else:
        print('Run Command: {}'.format(command))
        print()


'''
Section 1: Planning and Installation
'''
def section1():
    print("### Start of Section 1 ###\n")
    ## Section 1.1 Ensure the Pre-Installation Planning Checklist Has Been Implemented
    print("Ensure the Pre-Installation Planning Checklist in Section 1.1 of the CIS Apache 2.4 Benchmark has been implemented.\n")
    
    ## Section 1.2 Ensure the Server Is Not a Multi-Use System
    ret = subprocess.run("systemctl list-units --all --type=service --no-pager | grep -w active | grep running > active_running_services.txt", capture_output=True, shell=True)
    active_running_output = ret.stdout.decode()
    print("All active and running services are saved to active_running_services.txt. Disable or uninstall unneeded services.\n")

    if remedy:
        disable_service = ""
        while not disable_service == "y" and not disable_service == "n":
            disable_service = input("Disable service(s)? (Y/N) ").rstrip().lower()
            if disable_service == "y":
                services_to_disable = input("Enter service(s) to disable (separated by comma): ")
                services_to_disable_list = services_to_disable.split(",")

                for service in services_to_disable_list:
                    service = service.strip().replace("\n", "")

                    ret2= subprocess.run("systemctl stop " + service, capture_output=True, shell=True)
                    ret3 = subprocess.run("systemctl disable " + service, capture_output=True, shell=True)

                    if ret2.returncode!=0:
                        print("Failed to stop " + service)
                    
                    if ret3.returncode!=0:
                        print("Failed to disable " + service)

            elif disable_service == "n" :
                print("No services will be disabled.\n")
                
            else:
                continue

    ## Section 1.3  Ensure Apache Is Installed From the Appropriate Binaries
    print("Ensure that Apache is installed with \'apt-get install apache2\', instead of downloading and installing custom Apache binaries.")

    print("\n### End of Section 1 ###")


'''
Pre-requisites checks:

1. Check if root.
2. Check if Apache is installed.
3. Check if Apache is running.

'''
def prereq_check():
    # id -u checks for user id. 0 means root, non-zero means normal user.
    command = "id -u"
    ret = subprocess.run(command, capture_output=True, shell=True)
    user_id = int(ret.stdout.decode())

    if user_id != 0:
        print("Root required. Please run as root!")
        exit(-1)
    else:
        install_apache = ""

        ret = subprocess.run("apachectl", capture_output=True, shell=True)
        apachectl_error_code = ret.returncode

        # If Apache is not installed.
        if apachectl_error_code!=1:
            while not install_apache == "y" and not install_apache == "n":
                install_apache = input("Apache is not installed. Install Apache? (Y/N) ").rstrip().lower()
                if install_apache == "y":
                    print("Installing Apache...\n")
                    subprocess.run("apt-get install apache2 -y >/dev/null 2>&1", shell=True)
                    
                elif install_apache == "n":
                    print("Apache will not be installed.")
                    print("Script Terminated.")
                    exit(-1)
                    
                else:
                    continue

        # If Apache is installed, check if Apache is running.
        else:
            print("Apache is installed.")
            run_apache = ""
            
            ret = subprocess.run("systemctl is-active --quiet apache2 >/dev/null 2>&1", capture_output=True, shell=True)
            apache2_error_code = ret.returncode
            
            # If Apache is not running, prompt user to run Apache.
            if apache2_error_code!=0:
                while not run_apache == "y" and not run_apache == "n":
                    run_apache = input("Apache is not running. Start Apache? (Y/N) ").rstrip().lower()
                    if run_apache == "y":
                        print("Starting Apache...\n")
                        subprocess.run("service apache2 start", shell=True)
                        
                    elif run_apache == "n":
                        print("Apache will not be started.")
                        print("Script Terminated.")
                        exit(-1)
                        
                    else:
                        continue
            else:
                print("Apache is running.\n")

    dirs = os.listdir('conf')
    if len(dirs):
        print('Config files found in conf folder! Removing files...\n')
        shutil.rmtree('conf')
        os.mkdir('conf')


if __name__ == '__main__':
    toolDesc = ('Web Baseline Analyzer.\n' +
                'This tool is a targeted web server auditing and hardening tool based on the CIS Apache 2.4 Benchmark.')
    parser = argparse.ArgumentParser(description=toolDesc, formatter_class=RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('-r', action='store_true', help='Run script with this option to automatically perform remedies')
    group.add_argument('-e', action='extend', nargs='+', type=int, metavar=(1, 2), help='Enter list of sections to perform audit (E.g. 3 5 6)')
    group.add_argument('-d', action='extend', nargs='+', type=int, metavar=(1, 2), help='Enter list of sections to skip audit (E.g. 3 5 6)')

    args = parser.parse_args()
    remedy = args.r

    sectionsAudit = {1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12}

    if args.e:
        sectionsAudit = args.e
    elif args.d:
        sectionsAudit -= set(args.d)

    prereq_check()

    # Goal: Determine web server configuration dir
    webSerDir = r'/etc/apache2'
    if not os.path.isdir(webSerDir):
        webSerDir = input('Enter Configuration Folder Location: ')
    
    apacheConfFile = '{}/apache2.conf'.format(webSerDir)
    if not os.path.isfile(apacheConfFile):
        apacheConfFile = input('Enter Main Configuration File Location: ')

    # Get Apache Environment Variables
    envVarPath = '{}/envvars'.format(webSerDir)
    while not os.path.isfile(envVarPath):
        envVarPath = input('Enter path to environment variable file: ')
    
    envVars = [i.split('export ')[1].split('=') for i in os.popen('cat {} | grep export'.format(envVarPath)).read().split('\n') if i and i[0] != '#']

    varDict = {}
    for var in envVars:
        if len(var) == 2:
            varDict[var[0]] = var[1]


    for section in list(sectionsAudit):
        if section == 1:
            section1()
        elif section == 2:
            modCheck, modules = section24.section2Audit()
            section24.section2Analyze(modCheck, modules, remedy)
        elif section == 3:
            section24.section3Audit(apacheConfFile, varDict, webSerDir, remedy)
        elif section == 4:
            section24.section4Audit(apacheConfFile, webSerDir, remedy)
        elif section == 5:
            print("### Start of Section 5 ###\n")
            section_5_and_9.section_5_methods()
            print("\n### End of Section 5 ###")
        elif section == 6:
            section6.section6Audit(webSerDir, apacheConfFile, varDict, remedy)
        elif section == 7:
            print("### Start of Section 7 ###\n")
            section78.fullSect7Audit(remedy)
            print("\n### End of Section 7 ###")
        elif section == 8:
            print("### Start of Section 8 ###\n")
            section78.fullSect8Audit(apacheConfFile, remedy)
            print("\n### End of Section 8 ###")
        elif section == 9:
            print("### Start of Section 9 ###\n")
            section_5_and_9.section_9_methods()
            print("\n### End of Section 9 ###")
        elif section == 10:
            section1012.section10(apacheConfFile, remedy)
        elif section == 11:
            section1012.section11(remedy)
        elif section == 12:
            section1012.section12(remedy)

    
    # Reload apache2 server if remedy were automatically ran
    if remedy:
        print('Reloading apache2 to apply changes')
        commandRun('service apache2 reload')
    else:
        dirs = os.listdir('conf')
        if len(dirs):
            print('Updated config files can be found in the conf folder')
            print('Replace the originals with these to apply changes')
        print('Remember to reload Apache after applying the changes')
