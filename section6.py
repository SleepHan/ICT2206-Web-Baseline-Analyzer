import os
import re
import sys
import subprocess


'''
Will either run or print the command given based on the remedy flag
'''
def commandRun(command):
    if remedy:
        os.system(command)
    else:
        print('Run Command: {}'.format(command))
        print()


'''
Section 6: Operations - Logging, Monitoring and Maintenance
'''
def section6Audit():
    print("### Start of Section 6 ###\n")
    global apacheConfContent
    apacheConfContentSplit = apacheConfContent.split('\n')

    # 6.1 Ensure Error Log Filename and Severity Level are Configured Correctly
    # Get LogLevel for main level, ignore the rest (E.g. Found in directives)
    for index in range(len(apacheConfContentSplit)):
        line = apacheConfContentSplit[index]
        if 'LogLevel' in line:
            # Ensure that line is not a comment or from some directive
            if line[0] not in ['#', '\t']:
                print('Checking LogLevel Specifications')
                values = line.split()
                unspecLevel = coreLevel = update = False
                for valIndex in range(1, len(values)):
                    # Look for unspecified module log level
                    if ':' not in values[valIndex]:
                        unspecLevel = True
                        print('General Log Level: {}'.format(values[valIndex]))

                        # Ensure level is at notice
                        if values[valIndex] != 'notice':
                            print('Recommended Log Level: notice')
                            values[valIndex] = 'notice'
                            update = True

                        # Ensure element is the first entry
                        if valIndex != 1:
                            print('Recommended to put general log level first')
                            values[1], values[valIndex] = values[valIndex], values[1]
                            update = True

                        print()

                    # Look for core module log level
                    elif values[valIndex].startswith('core:'):
                        coreLevel = True
                        coreLogLevel = values[valIndex].split(':')[1]
                        print('Core Module Log Level: {}'.format(coreLogLevel))

                        # Check if core module log level is appropriate
                        if coreLogLevel != 'info':
                            print('Recommended Core Module Log Level: info')
                            values[valIndex] = 'core:info'

                        print()

                # Insert into the appropriate indexes if log levels are not found
                if not unspecLevel:
                    print('General Log Level Not Found')
                    print('Adding LogLevel notice\n')
                    values.insert(1, 'notice')
                
                if not coreLevel:
                    print('Core Module Log Level Not Found')
                    print('Adding LogLevel core:info\n')
                    values.insert(2, 'core:info')

                if update:
                    if remedy:
                        print('Updating LogLevel directive in {}\n'.format(apacheConfFile))
                        apacheConfContentSplit[index] = ' '.join(values)
                    else:
                        print('Update LogLevel directiive to this:')
                        print(' '.join(values))
                        print()
                    


    # 6.2 Ensure Sysloog Facility is Configured for Error Logging

    # 6.3 Ensure Server Access Log is Configured Correctly

    # 6.4 Ensure Log Storage and Rotation is Configured Correctly

    # 6.5 Ensure Applicable Patches are Applied
    # Check if ppa:obdrej/apache2 respository is added
    repo = False
    print('\nLooking for Apache2 Updates')
    res = os.popen('ls /etc/apt/sources.list.d | grep ondrej-ubuntu-apache2').read()
    
    if not res:
        if remedy:
            print('Repository not added to apt! Adding repository...')
            os.system('apt update >/dev/null 2>&1\nadd-apt-repository ppa:ondrej/apache2 -y >/dev/null 2>&1\napt update >/dev/null 2>&1')
            repo = True
        else:
            print('Repository not added to apt! Unable to update Apache2...')
            print('Run the following commands')
            print('sudo apt update\nsudo add-apt-repository ppa:ondrej/apache2 -y\nsudo apt update')
    else:
        repo = True

    # Look for available Apache2 upgrades
    if repo:
        res = os.popen('apt list --upgradable 2>&1 | grep apache2').read()
        if res:
            print('Newer version of Apache2 found')
            if remedy:
                apCurVer = os.popen('apache2 -v | grep version').read().split()[2]
                print('Updating Apache2...')
                os.system('apt install apache2 -y >/dev/null 2>&1')
                apNewVer = os.popen('apache2 -v | grep version').read().split()[2]
                print('Version Update: {} --> {}\n'.format(apCurVer, apNewVer))
            else:
                print('Run command: sudo apt install apache2\n')
        else:
            print('Apache2 up-to-date\n')


    # 6.6 Ensure ModSecurity is Installed and Enabled
    # Check if security2_module is loaded
    print('\nChecking ModSecurity module')
    res = os.popen('apache2ctl -M 2>/dev/null | grep security2_module').read()

    if not res:
        print('ModSecurity module disabled')
        # Check if module is installed
        res = os.popen('ls {}/mods-available | grep security2'.format(webSerDir)).read()
        installed = False

        if not res:
            # Install module
            if remedy:
                print('ModSecurity module not installed! Installing module...')
                os.system('apt-get install libapache2-mod-security2 -y >/dev/null 2>&1')
                installed = True
            else:
                print('ModSecurity module not installed! Unable to enable module...')
                print('Run command: apt-get install libapache2-mod-security2 -y')
        else:
            installed = True

        # Enable module
        if installed:
            commandRun('a2enmod security2')
    else:
        print('ModSecurity module enabled\n')

    # 6.7 Ensure OWASP ModSecurity Core Rule Set is Installed and Enabled
    print("\n### End of Section 6 ###")


'''
Pre-requisites checks:

1. Check if root.
'''
def prereq_check():
    # id -u checks for user id. 0 means root, non-zero means normal user.
    command = "id -u"
    ret = subprocess.run(command, capture_output=True, shell=True)
    user_id = int(ret.stdout.decode())

    if user_id != 0:
        print("Script requires root permissions to continue...")
        exit(-1)
    else:
        install_apache = ""

        ret = subprocess.run("apachectl", capture_output=True, shell=True)
        apachectl_error_code = ret.returncode

        # If Apache is not installed.
        if apachectl_error_code!=1:
            while not re.match(r"^y$", install_apache) and not re.match(r"^n$", install_apache):
                install_apache = input("Apache is not installed. Install Apache? (Y/N) ").rstrip().lower()
                if re.match(r"^y$", install_apache):
                    print("Installing Apache...\n")
                    subprocess.run("apt-get install apache2 -y >/dev/null 2>&1", shell=True)
                    
                elif re.match(r"^n$", install_apache) :
                    print("Apache will not be installed.")
                    print("Script Terminated.")
                    exit(-1)
                    
                else:
                    continue

        # If Apache is installed, check if Apache is running.
        else:
            run_apache = ""
            
            ret = subprocess.run("systemctl is-active --quiet apache2 >/dev/null 2>&1", capture_output=True, shell=True)
            apache2_error_code = ret.returncode
            

            if apache2_error_code!=0:
                while not re.match(r"^y$", run_apache) and not re.match(r"^n$", run_apache):
                    run_apache = input("Apache is not running. Start Apache? (Y/N) ").rstrip().lower()
                    if re.match(r"^y$", run_apache):
                        print("Starting Apache...\n")
                        subprocess.run("service apache2 start", shell=True)
                        
                    elif re.match(r"^n$", run_apache) :
                        print("Apache will not be started.")
                        print("Script Terminated.")
                        exit(-1)
                        
                    else:
                        continue


'''
Remedy check: Check if remedy option is enabled (-r).
'''
def remedy_check():
    remedy = False
    if len(sys.argv) == 2 and re.match(r"^-r$",sys.argv[1]):
        print("Remedy option enabled.\n")
        remedy = True
    return remedy


if __name__ == '__main__':
    prereq_check()
    remedy = remedy_check()

    # Goal: Determine web server configuration dir
    webSerDir = r'/etc/apache2'
    if not os.path.isdir(webSerDir):
        webSerDir = input('Enter Configuration Folder Location: ')
    
    apacheConfFile = '{}/apache2.conf'.format(webSerDir)
    if not os.path.isfile(apacheConfFile):
        apacheConfFile = input('Enter Main Configuration File Location: ')

    with open(apacheConfFile) as f:
        apacheConfContent = f.read()

    section6Audit()

    # Reload apache2 server if remedy were automatically ran
    if remedy:
        commandRun('service apache2 reload')
    else:
        print('Remember to reload apache after applying the changes')