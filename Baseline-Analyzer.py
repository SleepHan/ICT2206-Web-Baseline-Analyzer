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
Section 1: Planning and Installation
'''
def section1():
    print("### Start of Section 1 ###\n")
    ## Section 1.1 Ensure the Pre-Installation Planning Checklist Has Been Implemented
    print("Ensure the Pre-Installation Planning Checklist in Section 1.1 of the CIS Apache 2.4 Benchmark has been implemented.")
    
    ## Section 1.2 Ensure the Server Is Not a Multi-Use System
    ret = subprocess.run("systemctl list-units --all --type=service --no-pager | grep -w active | grep running > active_running_services.txt", capture_output=True, shell=True)
    active_running_output = ret.stdout.decode()
    print("All active and running services are saved to active_running_services.txt. Disable or uninstall unneeded services.")

    if remedy:
        disable_service = ""
        while not re.match(r"^y$", disable_service) and not re.match(r"^n$", disable_service):
            disable_service = input("Disable service(s)? (Y/N) ").rstrip().lower()
            if re.match(r"^y$", disable_service):
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

            elif re.match(r"^n$", disable_service) :
                print("No services will be disabled.\n")
                
            else:
                continue

    ## Section 1.3  Ensure Apache Is Installed From the Appropriate Binaries
    print("Ensure that Apache is installed with \'apt-get install apache2\', instead of downloading custom Apache binaries.")

    print("\n### End of Section 1 ###")


'''
Section 2: Minimize Apache Modules
Separates modules to statically or dynamically loaded
'''
def filterMods(modList):
    staticMods = []
    dynamicMods = []

    if len(modList):
        for mod in modList:
            if mod == 'Log_Config':
                staticMods.append('mod')
            else:
                modName = mod[1:-9]
                modType = mod[-7:-1]
                if modType == 'static':
                    staticMods.append(modName)
                else:
                    dynamicMods.append(modName)

    return staticMods, dynamicMods


'''
Section 2: Minimize Apache Modules
Gives the appropriate fix for statically or dynamically loaded modules
'''
def modDisable(modList):
    staticMod, dynamicMod = filterMods(modList)
    if len(staticMod):
        print('Static Modules to Disable')
        pathToDis = input('Enter the path to your Apache source folder: ')
        prefix = input('Enter location of server installation: ')
        configStr = './configure'
        for mod in staticMod:
            if mod != 'Log_Config':
                modName = mod.split('_module')[0].replace('_', '-')
                configStr += ' --disable-{}'.format(modName)
        

        commandStr = ('cd {}'.format(pathToDis) + '\n'
                        + '{} --prefix={}'.format(configStr, prefix) + '\n'
                        + 'make\n'
                        + 'make install\n'
                        + '{}/bin/apachectl -k graceful-stop'.format(prefix) + '\n'
                        + '{}/bin/apachectl -k start'.format(prefix))

        commandRun(commandStr)

    if len(dynamicMod):
        print('Shared Modules to Disable')
        print(dynamicMod)
        disCom = 'a2dismod -f'
        for mod in dynamicMod:
            modName = mod.split('_module')[0]
            disCom += ' {}'.format(modName)

        commandRun(disCom)


'''
Section 2: Minimize Apache Modules (Audit)
'''
def section2Audit():
    print("### Start of Section 2 ###\n")
    modules = {}
    modCheck = [False, False, False, False, False, False, False, False, False]

    # Only Necessary Authz and Authn Mods (Enabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep auth._').read().split('\n')[:-1]
    res.extend(os.popen('apache2ctl -M 2>/dev/null | grep ldap').read().split('\n')[:-1])
    if len(res):
        modCheck[0] = True
        modules[0] = res

    # Log Config Mod (Enabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep log_config').read().split('\n')[:-1]
    if len(res):
        modCheck[1] = True

    # WebDAV Mods (Disabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep dav_[[:print:]]+module').read().split('\n')[:-1]
    if not len(res):
        modCheck[2] = True
    else:
        modules[2] = res

    # Status Mod (Disabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep status_module').read().split('\n')[:-1]
    if not len(res):
        modCheck[3] = True
    else:
        modules[3] = res

    # AutoIndex Mod (Disabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep autoindex_module').read().split('\n')[:-1]
    if not len(res):
        modCheck[4] = True
    else:
        modules[4] = res

    # Proxy Mods (Disabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep proxy_').read().split('\n')[:-1]
    if not len(res):
        modCheck[5] = True
    else:
        modules[5] = res

    # User Directories Mod (Disabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep userdir').read().split('\n')[:-1]
    if not len(res):
        modCheck[6] = True
    else:
        modules[6] = res

    # Info Mod (Disabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep info_module').read().split('\n')[:-1]
    if not len(res):
        modCheck[7] = True
    else:
        modules[7] = res

    # Basic and Digest Authn Mods (Disabled)
    res = os.popen('apache2ctl -M 2>/dev/null | grep auth_basic').read().split('\n')[:-1]
    res.extend(os.popen('apache2ctl -M 2>/dev/null | grep auth_digest').read().split('\n')[:-1])
    if not len(res):
        modCheck[8] = True
    else:
        modules[8] = res

    return modCheck, modules


'''
Section 2: Minimize Apache Modules (Analyze)
'''
def section2Analyze(modCheck, modules):
    modDisList = []
    if modCheck[0]:
        print('Authentication and Authorization modules found')
        print('Only enable the necessary modules')
        print(modules[0])
        print()

    if not modCheck[1]:
        print('Log_Config Module Disabled!!')
        modDisList.append('Log_Config')

    if not modCheck[2]:
        print('WebDAV Modules Enabled!!')
        modDisList.extend(modules[2])

    if not modCheck[3]:
        print('Status Module Enabled!!')
        modDisList.extend(modules[3])

    if not modCheck[4]:
        print('AutoIndex Module Enabled!!')
        modDisList.extend(modules[4])

    if not modCheck[5]:
        print('Proxy Modules Enabled!!')
        modDisList.extend(modules[5])

    if not modCheck[6]:
        print('UserDir Module Enabled!!')
        modDisList.extend(modules[6])

    if not modCheck[7]:
        print('Info Module Enabled!!')
        modDisList.extend(modules[7])

    if not modCheck[8]:
        print('Outdated Auth Modules Enabled!!')
        modDisList.extend(modules[8])

    if len(modDisList):
        modDisable(modDisList)

    print("\n### End of Section 2 ###")


'''
Section 3: Principles, Permissions and Ownerships
'''
def section3Audit():
    print("### Start of Section 3 ###\n")

    docRoot = os.popen('grep -i DocumentRoot {}/sites-available/000-default.conf'.format(webSerDir)).read().split()[-1]

    # 3.1
    # [User Exist, Group Exist]
    chkList = [False, False]

    # ADD APACHE USER (MANUAL FIX) - Done
    res = os.popen('grep -i ^User {}'.format(apacheConfFile)).read()
    if res:
        user = res.split('User ')[1].replace('\n', '')
        chkList[0] = True
    else:
        print('No Apache user found')
        print('Ensure there is a User directive present in the {} file'.format(apacheConfFile))
    
    # ADD APACHE GROUP (MANUAL FIX) -Done
    res = os.popen('grep -i ^Group {}'.format(apacheConfFile)).read()
    if res:
        group = res.split('Group ')[1].replace('\n', '')
        chkList[1] = True
    else:
        print('No Apache group found')
        print('Ensure there is a Group directive present in the {} file'.format(apacheConfFile))

    if chkList[0]:
        if user.startswith('${'):
            user = varDict[user[2:-1]]

        res = os.popen('grep ^UID_MIN /etc/login.defs').read()
        uidMin = int(res.split()[1])

        res = os.popen('id {}'.format(user)).read()
        ids = res.split()
        uid = int(ids[0][4:].split('(')[0])

        # REVERT TO DEFAULT/CREATE NEW USER (MANUAL FIX)
        if uid >= uidMin:
            print('Apache running as non-system account')
            print('Fixing methods:')
            print('1. Revert to default user account (www-data)')
            print('2. useradd <USER_NAME> --r -g {} -d {} -s /sbin/nologin'.format(group, docRoot))
            print()

        # REMOVE FROM SUDOER GROUP (MANUAL FIX)
        elif 'sudo' in ids[2]:
            print('Apache user has sudo privilege')
            print('Fixing Methods:')
            print('1. deluser {} sudo'.format(user))
            print()

        else:
            # Ensure Apache User Account has Invalid Shell
            if not os.popen('grep {} /etc/passwd | grep /sbin/nologin'.format(user)).read():
                print('Apache user should have an invalid login shell')
                commandRun('chsh -s /sbin/nologin {}'.format(user))

            # Ensure Apache User is Locked
            if os.popen('passwd -S {}'.format(user)).read().split()[1] != 'L':
                print('Apache user should be locked')
                commandRun('passwd -l {}'.format(user))

    # Ensure Apache Directories and Files are Owned by Root
    res = os.popen('find {} \! -user root'.format(webSerDir)).read()

    if res:
        print('Found apache directories/files not owned by root')
        commandRun('chown -R root {}'.format(webSerDir))

    # Ensure Group is Set Correctly on Apache Directories and Files
    res = os.popen('find {} \! -group root'.format(webSerDir)).read()

    if res:
        print('Found apache directories/files not in root group')
        commandRun('chgrp -R root {}'.format(webSerDir))

    # Ensure Other Write Access on Apache Directories and Files is Restricted
    res = os.popen('find -L {} \! -type l -perm /o=w'.format(webSerDir)).read()

    if res:
        print('Found apache directories/files with other write access')
        commandRun('chmod -R o-w {}'.format(webSerDir))

    # Ensure Group Write Access for Apache Directories and Files is Proeprly Restricted
    res = os.popen('find -L {} \! -type l -perm /g=w -ls'.format(webSerDir)).read()
    
    if res:
        print('Apache directories/files found with group write access')
        commandRun('chmod -R g-w {}'.format(webSerDir))

    # Ensure Core Dump Directory is Secured
    res = os.popen('grep -n CoreDumpDirectory {}'.format(apacheConfFile)).read().split('\n')[:-1]
    
    # Get the line number of the CoreDumpDirectory directive
    # Remove line from apache content
    if res:
        global apacheConfContent

        for line in res:
            lineNo = line.split(':', 1)[0]
            apacheConfContent.pop(int(lineNo) - 1)
        print('CoreDumpDirectory directive found in conf file')

    logDir = varDict['APACHE_LOG_DIR']
    res = os.popen('find {} -prune \! -user root'.format(logDir)).read()
    
    if res:
        print('Apache log directory not owned by root')
        commandRun('chown root {}'.format(logDir))

    res = os.popen('find {} -prune -perm /o=rwx'.format(logDir)).read()

    if res:
        print('Apache log directory accessible by others')
        commandRun('chmod o-rwx {}'.format(logDir))

    if chkList[1]:
        if group.startswith('${'):
            group = varDict[group[2:-1]]

        # Check if group is a system group
        res = os.popen('grep ^GID_MIN /etc/login.defs').read()
        gidMin = int(res.split()[1])

        res = os.popen('getent group {}'.format(group)).read()
        gid = int(res.split(':')[2])

        # REVERT TO DEFAULT/CREATE NEW GROUP (MANUAL FIX)
        if gid >= gidMin:
            print('Apache group ({}) is non-system'.format(group))
            print('Fixing methods:')
            print('1. Revert to default group (www-data)')
            print('2. groupadd -r <GROUP_NAME>')
            print()
        else:
            res = os.popen('find {} -prune \! -group {}'.format(logDir, group))
            if res:
                print('Apache log directory not owned by {} group'.format(group))
                commandRun('chgrp {} {}'.format(group, logDir))

            # Ensure Group Write Access for Document Root Directories and Files is Properly Restricted
            res = os.popen('find -L {} -group {} -perm /g=w -ls'.format(docRoot, group)).read()
            
            if res:
                print('DocumentRoot directories/files found with group write access')
                commandRun('find -L {} -group {} -perm /g=w -print | xargs chmod g-w'.format(docRoot, group))

    # Ensure Lock File is Secured
    lockDir = varDict['APACHE_LOCK_DIR']
    
    # CHANGE LOCK DIRECTORY (MANUAL FIX)
    if docRoot in lockDir:
        print('Lock directory in document root: {}'.format(lockDir))
        print('Move/Modify directory to one outside of {}'.format(docRoot))

    res = os.popen('find {} -prune \! -user root'.format(lockDir)).read()

    if res:
        print('Apache lock directory not owned by root')
        commandRun('chown root:root {}'.format(lockDir))

    res = os.popen('find {} -prune -perm /o+w'.format(lockDir)).read()
    
    if res:
        print('Apache lock directory writable by others')
        commandRun('chmod o-w {}'.format(lockDir))

    res = os.popen('df -PT {} | tail -n +2 | awk "{{print $2}}" '.format(lockDir)).read().split('\n')[0]

    # MOVE DIRECTORY TO LOCAL HARD DRIVE (MANUAL FIX)
    if res == 'nfs':
        print('Lock file directory is on an NFS mounted filesystem: {}'.format(lockDir))
        print('Move/Modify directory to a locally mounted file system (E.g. /var/lock/apache2)')
        
    # Ensure PID File is Secured
    res = os.popen('grep "PidFile " {}'.format(apacheConfFile)).read()
    pidFilePath = res.split(' ', 1)[1]
    
    if pidFilePath.startswith('${'):
        pidFilePath = varDict[pidFilePath[2:-2]]

    pidDir = pidFilePath.rsplit('/', 1)[0]

    # CHANGE PID DIRECTORY (MANUAL FIX)
    if docRoot in pidDir:
        print('PID directory in document root: {}'.format(pidDir))
        print('Move/Modify directory to one outside of {}'.format(docRoot))

    res = os.popen('find {} -prune \! -user root'.format(pidDir)).read()

    if res:
        print('Apache PID directory not owned by root')
        commandRun('chown root:root {}'.format(pidDir))
    
    res = os.popen('find {} -prune -perm /o+w'.format(pidDir)).read()
    
    if res:
        print('Apache PID directory writable by others')
        commandRun('chmod o-w {}'.format(pidDir))

    # Ensure ScoreBoard File is Secured
    res = os.popen('grep ScoreBoardFile {}'.format(apacheConfFile)).read().split('\n')[:-1]

    if res:
        for score in res:
            scoreBoardDir = score.split(' ', 1).rsplit('/', 1)

            # CHANGE SCOREBOARD DIRECTORY (MANUAL FIX)
            if docRoot in scoreBoardDir:
                print('ScoreBoardFile directory in document root: {}'.format(scoreBoardDir))
                print('Move/Modify directory to one outside of {}'.format(docRoot))

            res = os.popen('find {} -prune \! -user root'.format(scoreBoardDir)).read()

            if res:
                print('ScoreBoardFile directory not owned by root')
                commandRun('chown root:root {}'.format(scoreBoardDir))
            
            res = os.popen('find {} -prune -perm /o+w'.format(scoreBoardDir)).read()
            
            if res:
                print('ScoreBoardFile directory writable by others')
                commandRun('chmod o-w {}'.format(scoreBoardDir))

            res = os.popen('df -PT {} | tail -n +2 | awk "{{print $2}}" '.format(scoreBoardDir)).read().split('\n')[0]

            # MOVE DIRECTORY TO LOCAL HARD DRIVE (MANUAL FIX)
            if res == 'nfs':
                print('ScoreBoardFile directory is on an NFS mounted filesystem: {}'.format(scoreBoardDir))
                print('Move/Modify directory to a locally mounted file system')
 
    # Ensure Access to Special Purpose Application Writable Directories is Properly Restricted
    # Does not seem possible to do automatically, since we will require all the possible writable directories that the user will be having 

    print("\n### End of Section 3 ###")


'''
Section 4: Apache Access Control
Looks for the respective directives based on the pattern given
Runs the appropriate function to decide if any changes were made
'''
def handleDirective(pattern, content, confUpdate, isDir=False):
    res = re.finditer(pattern, content)

    confChanges = []

    for dir in res:
        dirField = dir.group()
        dirIndexes = dir.span()

        if dirField.split('\n')[1][0] == '#':
            continue

        # Root Directory
        elif dirField.split('\n')[0] in ['<Directory>', '<Directory />']:
            updatedField, changed = rootDirectory(dirField)
            if changed:
                print('Original Directive:\n{}'.format(dirField))

                print('\nUpdated Directive:\n{}\n'.format(updatedField))
                confChanges.append((dirIndexes, updatedField))

        else:
            updatedField, changed = webContent(dirField, isDir)
            if changed:
                print('Original Directive:\n{}'.format(dirField))

                print('\nUpdated Directive:\n{}\n'.format(updatedField))
                confChanges.append((dirIndexes, updatedField))

    if len(confChanges):
        content = updateConf(confChanges, content)
        confUpdate = True

    return content, confUpdate


'''
Section 4: Apache Access Control
Checks for the appropriate access control for the OS root directory
'''
def rootDirectory(dirField):
    dirSplit = dirField.split('\n')
    toRemove = []
    changed = False
    requireFound = False
    overrideFound = False
    for index in range(len(dirSplit)):
        line = dirSplit[index]

        # Ensure OverRide is Disabled for OS Root Directory
        if 'AllowOverride' in line:
            if 'AllowOverride None' in line:
                overrideFound = True
            else:
                toRemove.append(index)
                changed = True

        # Ensure Access to OS Root Directory is Denied by Default
        elif 'Require' in line:
            requireFound = True
            requireEndIndex = line.index('Require') + 8
            if line[requireEndIndex:] != 'all denied':
                dirSplit[index] = line[:requireEndIndex] + 'all denied'
                changed = True
        elif 'Deny' in line:
            toRemove.append(index)
            changed = True
        elif 'Allow' in line:
            toRemove.append(index)
            changed = True

    if not requireFound:
        dirSplit.insert(-1, '\tRequire all denied')
        changed = True

    if not overrideFound:
        dirSplit.insert(-1, '\tAllowOverride None')
        changed = True

    toRemove.reverse()
    for index in toRemove:
        dirSplit.pop(index)

    updatedField = '\n'.join(dirSplit)
    return updatedField, changed
    

'''
Section 4: Apache Access Control
Checks for the appropriate access control for directives
'''
def webContent(dirField, isDir=False):
    dirSplit = dirField.split('\n')
    print('Current checking directives for {}'.format(dirSplit[0]))
    toRemove = []
    changed = False
    requireFound = False
    overrideFound = False

    for index in range(len(dirSplit)):
        line = dirSplit[index]

        if 'AllowOverride' in line:
            if 'AllowOverride None' in line:
                overrideFound = True
            else:
                toRemove.append(index)
                changed = True
        elif 'Require' in line:
            print('Require statement found: {}'.format(line.replace('\t', '')))
            chk = input('Is the access given appropriate? (Y/N) ')

            # Get New Require Value
            if chk.lower() == 'n':
                newRequire = input('Enter new require directive value: ')
                if newRequire.startswith('Require '):
                    newRequire = newRequire[8:]
                requireEndIndex = line.index('Require') + 8
                dirSplit[index] = line[:requireEndIndex] + newRequire
                changed = True
            
            requireFound = True
            print()
        elif 'Deny' in line:
            toRemove.append(index)
            changed = True
        elif 'Allow' in line:
            toRemove.append(index)
            changed = True
        

    if not requireFound:
        dirSplit.insert(-1, '\tRequire all granted')
        changed = True

    if not overrideFound and isDir:
        dirSplit.insert(-1, '\tAllowOverride None')
        changed = True

    toRemove.reverse()
    for index in toRemove:
        dirSplit.pop(index)

    updatedField = '\n'.join(dirSplit)
    return updatedField, changed


'''
Section 4: Apache Access Control
Updates the configuration file content
'''
def updateConf(confChanges, confContent):
    newContent = []
    for change in reversed(confChanges):
        # Update Main Content String
        changeStr = confContent[change[0][0]:]
        confContent = confContent[:change[0][0]]

        # Update changeStr to new field/directive content
        newIndex = change[0][1] - change[0][0]
        updateStr = change[1] + changeStr[newIndex:]
        newContent.insert(0, updateStr)

    newContent.insert(0, confContent)

    return ''.join(newContent)


'''
Section 4: Apache Access Control
Removes any instances of the AllowOverrideList directive from the configuration content
'''
def rmAllowOverrideList(confContent):
    contentSplit = confContent.split('\n')
    toRemove = []
    for index in range(len(contentSplit)):
        line = contentSplit[index]
        if line:
            if line.split()[0] == 'AllowOverrideList':
                toRemove.append(index)

    if len(toRemove):
        print('Removing AllowOverrideList Directives')
        toRemove.reverse()
        for index in toRemove:
            print(contentSplit.pop(index))

    return '\n'.join(contentSplit)


'''
Section 4: Apache Access Control
'''
def section4Audit():
    # Getting List of Conf Files for Web Content to Analyze
    #   - apache2.conf
    #   - sites-enabled
    #       - *.conf
    print("### Start of Section 4 ###\n")
    confPaths = ['SERVER_CONFIG_FILE']
    confPaths.extend(os.popen('ls {}/sites-enabled/*.conf'.format(webSerDir)).read().split('\n')[:-1])
    
    for confFile in confPaths:
        if confFile == 'SERVER_CONFIG_FILE':
            global apacheConfContent
            content = apacheConfContent
        else:
            with open(confFile) as f:
                content = f.read()
        
        confUpdate = False

        # Directory directive
        pattern = '(<Directory[.\s\S]+?<\/Directory>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate, True)

        # DirectoryMatch directive
        pattern = '(<DirectoryMatch[.\s\S]+?<\/DirectoryMatch>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate)

        # Files directive
        pattern = '(<Files[.\s\S]+?<\/Files>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate)

        # FilesMatch directive
        pattern = '(<FilesMatch[.\s\S]+?<\/FilesMatch>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate)

        # Location directive
        pattern = '(<Location[.\s\S]+?<\/Location>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate)

        # LocationMatch directive
        pattern = '(<LocationMatch[.\s\S]+?<\/LocationMatch>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate)

        # Proxy
        pattern = '(<Proxy[.\s\S]+?<\/Proxy>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate)

        # ProxyMatch
        pattern = '(<ProxyMatch[.\s\S]+?<\/ProxyMatch>)'
        content, confUpdate = handleDirective(pattern, content, confUpdate)

        # Remove all AllowOverrideList directives
        content = rmAllowOverrideList(content)
        
        if confUpdate:
            if confFile == 'SERVER_CONFIG_FILE':
                apacheConfContent = content
            else:
                if remedy:
                    with open('{}.new'.format(confFile), 'w') as f:
                        f.write(content)
                    
                    print('\nAll changes are saved to {}.new. To reflect all changes, manually rename this file to {}.'.format(confFile, confFile))

    print("\n### End of Section 4 ###")


'''
Section 6: Operations - Logging, Monitoring and Maintenance
Updates the log directives for each VirtualHost
'''
def checkVirtualHost(pattern, errorLogFile, errorLogFaci, customLog, logFormatStrings):
    global apacheConfContent
    content = apacheConfContent
    res = re.finditer(pattern, content)

    confChanges = []
    fac = errorLogFaci.split(':')[1]
    logFile = errorLogFile.split()[1]

    for dir in res:
        changed = False
        dirField = dir.group()[1:]
        dirIndexes = dir.span()
        serverName = ''

        dirSplit = dirField.split('\n')
        indentLevel = dirSplit[0].split('<')[0] + '\t'
        fileFound = faciFound = customLogFound = False

        for index in range(len(dirSplit)):
            values = dirSplit[index].split()

            if values[0] == 'ServerName':
                serverName = ' '.join(values[1:])

            # Look for ErrorLog Directive
            elif values[0] == 'ErrorLog':
                errorLogEndIndex = dirSplit[index].index('ErrorLog') + 9

                # Check if facility is the same as the main configuration's
                if values[1].startswith('syslog'):
                    faciFound = True
                    sysSplit = values[1].split(':')
                    if sysSplit[1] != fac:
                        sysSplit[1] = fac
                        values[1] = ':'.join(sysSplit)
                        dirSplit[index] = dirSplit[index][:errorLogEndIndex] + ' '.join(values[1:])
                        changed = True
                
                # Check if directory is the same as the main configuration's
                else:
                    fileFound = True
                    if values[1].rsplit('/', 1)[0] != logFile.rsplit('/', 1)[0]:
                        values[1] = logFile.rsplit('/', 1)[0] + serverName + '-' + values[1].rsplit('/', 1)[1]
                        dirSplit[index] = dirSplit[index][:errorLogEndIndex] + ' '.join(values[1:])
                        changed = True

            # Look for CustomLog Directive
            elif values[0] == 'CustomLog':
                customLogFound = True
                customLogStartIndex = dirSplit[index].index('CustomLog')

                if len(logFormatStrings):
                    if not any(values[-1] == forStr.split()[-1] for forStr in logFormatStrings):
                        dirSplit[index] = dirSplit[index][:customLogStartIndex] +  ' '.join(values)
                        changed = True
                        

        if serverName:
            logFileSplit = errorLogFile.rsplit('/', 1)
            customLSplit = customLog.rsplit('/', 1)
            
            errorLogFile = logFileSplit[0] + '/{}-'.format(serverName) + logFileSplit[1]
            customLog = customLSplit[0] + '/{}-'.format(serverName) + customLSplit[1]

        if not fileFound:
            dirSplit.insert(-1, indentLevel + errorLogFile)
            changed = True

        if not faciFound:
            dirSplit.insert(-1,  indentLevel + errorLogFaci)
            changed  = True

        if not customLogFound:
            dirSplit.insert(-1, indentLevel + customLog)
            changed = True

        if changed:
            confChanges.append(((dirIndexes[0] + 1, dirIndexes[1]), '\n'.join(dirSplit)))

    if len(confChanges):
        content = updateConf(confChanges, content)
        apacheConfContent = content


'''
Section 6: Operations - Logging, Monitoring and Maintenance
'''
def section6Audit():
    print("### Start of Section 6 ###\n")
    global apacheConfContent
    apacheConfContentSplit = apacheConfContent.split('\n')
    logLevel = False
    errorLogFile = errorLogFaci = customLog = ''
    logFormatStrings = []
    customLogIndexes = []
    logFormatTokens = ['%h', '%l', '%u', '%t', '%r', '%>s', '%b', '%{{Referer}}i', '${{User-agent}}i']

    print('1. Logrotate')
    print('2. Piped Logging (Rotatelogs)')
    logRotateType = input('Choose logging method (Default 1): ')
    print()

    # 6.1 Ensure Error Log Filename and Severity Level are Configured Correctly
    # Get LogLevel for main level, ignore the rest (E.g. Found in directives)
    for index in range(len(apacheConfContentSplit)):
        line = apacheConfContentSplit[index]
        # Ensure LogLevel is of the appropriate level
        if 'LogLevel' in line:
            # Ensure that line is not a comment or from some directive
            if line[0] not in ['#', '\t']:
                print('Checking LogLevel Specifications')
                values = line.split()
                logLevel = True
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
                    print('Updating LogLevel directive in {}'.format(apacheConfFile))
                    print('{}\n'.format(' '.join(values)))
                    apacheConfContentSplit[index] = ' '.join(values)
                    
        # Ensure log files is appropriate
        # Ensure syslog facility is appropriate
        elif 'ErrorLog' in line:
            if line[0] not in ['#', '\t']:
                value = line.split()[1]
                sysLogFac = ['local0', 'loca1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']

                # 6.2 Ensure Sysloog Facility is Configured for Error Logging
                # Check syslog facility
                if value.startswith('syslog'):
                    print('Checking ErrorLog Syslog Facility')
                    fac = value.split(':')[1]
                    if fac not in sysLogFac:
                        print('Updating ErrorLog syslog Facility in {}'.format(apacheConfFile))
                        print('Old: {}'.format(line))
                        print('New: ErrorLog syslog:local7')
                        apacheConfContentSplit[index] = errorLogFaci = 'ErrorLog syslog:local7'

                    print()

                # Check log file
                # Check if log file location is writable by others
                else:
                    print('Checking ErrorLog File')
                    fileDir = value.rsplit('/')[0]
                    if fileDir.startswith('${'):
                        fileDir = varDict[fileDir[2:-1]]

                    res = os.popen('find -L {} -prune \! -perm o+w'.format(fileDir)).read()
                    if res:
                        print('Log directory is writable by others')
                        print('Fix Methods:')
                        print('1. Remove write permissions for others')
                        print('2. Move/Modify directory to something not writable by others')
                    else:
                        errorLogFile = line

                    print()

        # 6.3 Ensure Server Access Log is Configured Correctly
        elif 'LogFormat' in line:
            if line[0] not in ['#', '\t']:
                if all(token in line for token in logFormatTokens):
                    logFormatStrings.append(line.split(' ', 1)[1])
                elif line.split()[-1] == 'combined':
                    apacheConfContentSplit[index] = 'LogFormat "%h %l %u %t \"%r\" %>s %O \"%{{Referer}}i\" \"%{User-Agent}i\"" combined'
                    logFormatStrings.append(apacheConfContentSplit[index])

        elif 'CustomLog' in line:
            if line[0] not in ['#', '\t']:
                customLogIndexes.append(index)

    if len(customLogIndexes):
        customLogIndexes.reverse()
        print(customLogIndexes)
        for customIndex in customLogIndexes:
            line = apacheConfContentSplit[customIndex]

            if len(logFormatStrings):
                if any(line.split()[-1] == value.split()[-1] for value in logFormatStrings):
                    customLog = line
                elif all (token in line for token in logFormatTokens):
                    customLog = line
                else:
                    apacheConfContentSplit.pop(customIndex)
            elif all (token in line for token in logFormatTokens):
                customLog = line
            else:
                apacheConfContentSplit.pop(customIndex)

    apacheConfContent = '\n'.join(apacheConfContentSplit)

    if not logLevel:
        print('LogLevel directive not found. Adding directive...')
        print('LogLevel notice core:info')
        apacheConfContent += '\nLogLevel notice core:info'

    if not errorLogFile:
        print('ErrorLog directive to log file not found. Adding directive...')
        print('ErrorLog ${APACHE_LOG_DIR}/error.log\n')
        errorLogFile = '\nErrorLog ${APACHE_LOG_DIR}//error.log'
        apacheConfContent += errorLogFile

    if not errorLogFaci:
        print('ErrorLog directive to syslog facility not found. Adding directive...')
        print('ErrorLog syslog:local7\n')
        errorLogFaci = '\nErrorLog syslog:local7'
        apacheConfContent += errorLogFaci
    
    if not customLog:
        print('CustomLog directive not found.')

        if logRotateType == '2':
            defaultLogFile = '"|bin/rotatelogs -l ${{APACHE_LOG_DIR}}/access.log 86400"'
        else:
            defaultLogFile = '${{APACHE_LOG_DIR}}/access.log'

        if len(logFormatStrings) == 0:
            print('No LogFormat directives found. Adding directive as explicit string...')
            print('CustomLog {} "%h %l %u %t \"%r\" %>s %O \"%{{Referer}}i\" \"%{User-Agent}i\""\n'.format(defaultLogFile))
            customLog = 'CustomLog {} "%h %l %u %t \"%r\" %>s %O \"%{{Referer}}i\" \"%{User-Agent}i\""'.format(defaultLogFile)
        
        elif len(logFormatStrings) > 1:
            print('Choose the log format to use')
            for index in range(len(logFormatStrings)):
                print('{}. {}'.format(index, logFormatStrings[index]))
            logFormatIndex = input('Selct 1 - {}: '.format(len(logFormatStrings)))
            logFormatName = logFormatStrings[logFormatIndex - 1].split()[-1]
            print('Adding directive with {} nickname\n'.format(logFormatName))
            customLog = 'CustomLog {} {}\n'.format(defaultLogFile, logFormatName)
        
        else:
            logFormatName = logFormatStrings[0].split()[-1]
            print('Adding directive with {} nickname\n'.format(logFormatName))
            customLog = 'CustomLog {} {}\n'.format(defaultLogFile, logFormatName)

        apacheConfContent += customLog

    print('Updating Virtual Host Directives\n')
    pattern = '(\n<VirtualHost[.\s\S]+?<\/VirtualHost>)'
    checkVirtualHost(pattern, errorLogFile, errorLogFaci, customLog, logFormatStrings)

    # 6.4 Ensure Log Storage and Rotation is Configured Correctly
    if logRotateType == '1':
        with open('/etc/logrotate.d/apache2') as f:
            content = f.readlines()
        linesToLookFor = ['missingok', 'notifempty', 'sharedscripts']
        
        for line in content:
            conf = line.split()
            if len(conf) == 1 and conf[0] in linesToLookFor:
                linesToLookFor.remove(conf[0])
        
        if len(linesToLookFor):
            for line in linesToLookFor:
                content.insert(1, '    {}\n'.format(line))

        with open('/etc/logrotate.d/apache2', 'w') as f:
            f.write(''.join(content))

        with open('/etc/logrotate.conf') as f:
            content = f.readlines()
        
        changed = False
        for index in range(len(content)):
            if content[index].startswith('rotate'):
                rotNum = int(content[index].split()[-1])
                if rotNum != 13:
                    print('Changing keep 13 weeks of backlogs')
                    content[index] = 'rotate 13\n'
                    changed = True
        
        if changed:
            with open('/etc/logrotate.conf', 'w') as f:
                f.write(''.join (content))
        else:
            print('Log Rotation configuration all-good\n')

    else:
        print('Ensure that logs are retained for at least 13 weeks\n')


    # 6.5 Ensure Applicable Patches are Applied
    # Check if ppa:obdrej/apache2 respository is added
    repo = False
    print('Looking for Apache2 Updates')
    res = os.popen('ls /etc/apt/sources.list.d | grep ondrej-ubuntu-apache2').read()
    
    if not res:
        if remedy:
            print('Repository not added to apt! Adding repository...\n')
            os.system('apt update >/dev/null 2>&1\nadd-apt-repository ppa:ondrej/apache2 -y >/dev/null 2>&1\napt update >/dev/null 2>&1')
            repo = True
        else:
            print('Repository not added to apt! Unable to update Apache2...')
            print('Run the following commands')
            print('sudo apt update\nsudo add-apt-repository ppa:ondrej/apache2 -y\nsudo apt update\n')
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
    print('Checking ModSecurity module')
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
                os.system('cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf')
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
        # Check if mod security configuration file is set
        if not os.path.isfile('/etc/modsecurity/modsecurity.conf'):
            # Look for mod security recommended configuration file
            if not os.path.isfile('/etc/modsecurity/modsecurity.conf-recommended'):
                print('Unable to find modsecurity configuration file!')
                print('You can get the default configuration file can be found at https://github.com/SpiderLabs/ModSecurity/blob/v3/master/modsecurity.conf-recommended')
                print('Download and install it in /etc/modsecurity')
            else:
                os.system('cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf')
        
        print('ModSecurity module enabled\n')

    # 6.7 Ensure OWASP ModSecurity Core Rule Set is Installed and Enabled
    # Check if OWASP ModSecurity CRS is installed
    print('Checking OWASP ModSecurity CRS Status')
    res = os.popen('ls /etc/apache2/modsecurity.d | grep owasp-modsecurity-crs-*').read()

     # Installing
    if not res:
        
        commandLine = ('cd {}\n'.format(webSerDir) + 
                        'mkdir modsecurity.d >/dev/null 2>&1\n' +
                        'cd modsecurity.d\n' +
                        'wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/refs/tags/v3.2.0.tar.gz >/dev/null 2>&1\n' + 
                        'tar -xvzf v3.2.0.tar.gz >/dev/null 2>&1\n' +
                        'cd owasp-modsecurity-crs-3.2.0\n' +
                        'mv crs-setup.conf.example crs-setup.conf\n' +
                        'mv rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf\n' +
                        'mv rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf\n')
        
        if remedy:
            print('OWASP ModSecurity CRS not installed. Installing...')

            os.system(commandLine)

            # Update /etc/apache2/mods-available/security2.conf
            with open('/etc/apache2/mods-available/security2.conf') as f:
                content = f.readlines()

            ifModEndIndex = content.index('</IfModule>')
            content.insert(ifModEndIndex, '\tInclude modsecurity.d/owasp-modsecurity-crs-3.2.0/crs-setup.conf\n')
            content.insert(ifModEndIndex, '\tInclude modsecurity.d/owasp-modsecurity-crs-3.2.0//rules/*.conf\n')
            newContent = ''.join(content)

            with open('/etc/apache2/mods-available/security2.conf', 'w') as f:
                f.write(newContent)

            os.system('service apache2 reload')
        else:
            print('OWASP ModSecurity CRS not installed')
            print('Run these commands to install/download OWASP ModSecurity CRS')
            print(commandLine)

            print('\nAdd the following lines to the mods-enabled/security2.conf file')
            print('Include modsecurity.d/owasp-modsecurity-crs-3.2.0/crs-setup.conf')
            print('Include modsecurity.d/owasp-modsecurity-crs-3.2.0//rules/*.conf')

            print('\nservice apache2 reload')

    owaspFilePath = '/etc/apache2/modsecurity.d/owasp-modsecurity-crs-3.2.0'
    if not os.path.isfile('{}/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf'.format(owaspFilePath)):
        os.system('mv {}/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example {}/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf'.format(owaspFilePath, owaspFilePath))

    if not os.path.isfile('{}/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf'.format(owaspFilePath)):
        os.system('mv {}/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example {}/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf'.format(owaspFilePath, owaspFilePath))

    # Check the threshold levels are of the appropriate levels
    check = True
    ruleCount = os.popen("find /etc/apache2/modsecurity.d/owasp-modsecurity-crs-3.2.0 -name '*.conf' | xargs grep '^SecRule ' | wc -l").read()
    res = os.popen('find /etc/apache2/modsecurity.d/owasp-modsecurity-crs-3.2.0 -name "*.conf" | xargs egrep -v "^\s*#" | grep "setvar:\'tx.inbound_anomaly_score_threshold="').read()
    if res:
        inConfFile = res.split(':', 1)[0]
        inThreshold = res.split('\n')[0].split()[-1].split('=')[1][0]
    else:
        inConfFile = inThreshold = None

    res = os.popen('find /etc/apache2/modsecurity.d/owasp-modsecurity-crs-3.2.0 -name "*.conf" | xargs egrep -v "^\s*#" | grep "setvar:\'tx.outbound_anomaly_score_threshold="').read()
    if res:
        outConfFile = res.split(':', 1)[0]
        outThreshold = res.split('\n')[0].split()[-1].split('=')[1][0]
    else:
        outConfFile = outThreshold = None

    res = os.popen('find /etc/apache2/modsecurity.d/owasp-modsecurity-crs-3.2.0 -name "*.conf" | xargs egrep -v "^\s*#" | grep "setvar:\'tx.paranoia_level="').read()
    if res:
        paConfFile = res.split(':', 1)[0]
        paThreshold = res.split('\n')[0].split()[-1].split('=')[1][0]
    else:
        paConfFile = paThreshold = False

    if int(ruleCount.split('\n')[0]) < 325:
        print('OWASP ModSecurity CRS does not seem to be enabled. Please check if CRS was installed properly...')
        check = False
    else:
        if inThreshold == None:
            print('Inbound Anomaly Theshold not found')
            print('Please check if CRS was installed properly')
        elif int(inThreshold) > 5:
            print('Inbound Anomaly Threshold found to be more than 5')
            print('Source File: {}'.format(inConfFile))
            print('Recommended level: 5 or less')
            if remedy:
                with open(inConfFile) as f:
                    content = f.readlines()

                for index in range(len(content)):
                    if 'tx.inbound_anomaly_score_threshold' in content[index]:
                        content[index] = content[index][:-4] + '5\'"'
                
                with open(inConfFile, 'w') as f:
                    f.write(''.join(content))
            check = False
        
        if outThreshold == None:
            print('Outbound Anomaly Threshold not found')
            print('Please check if CRS was installed properly')
        elif int(outThreshold) > 4:
            print('Outbound Anomaly Threshold found to be more than 4')
            print('Source File: {}'.format(outConfFile))
            print('Recommended level: 4 or less')
            if remedy:
                with open(outConfFile) as f:
                    content = f.readlines()

                for index in range(len(content)):
                    if 'tx.inbound_anomaly_score_threshold' in content[index]:
                        content[index] = content[index][:-4] + '4\'"'
                
                with open(outConfFile, 'w') as f:
                    f.write(''.join(content))
            check = False

        if paThreshold == None:
            print('Paranoia Level not found')
            print('Please check if CRS was installed properly')
        elif int(paThreshold) < 1:
            print('Paranoia found to be less than 1')
            print('Source File: {}'.format(paConfFile))
            print('Recommended level: 1 or more')
            if remedy:
                with open(paConfFile) as f:
                    content = f.readlines()

                for index in range(len(content)):
                    if 'tx.inbound_anomaly_score_threshold' in content[index]:
                        content[index] = content[index][:-4] + '1\'"'
                
                with open(paConfFile, 'w') as f:
                    f.write(''.join(content))
            check = False

    if check:
        print('Status all-good')

    apacheConfContent = '\n'.join(apacheConfContentSplit)
    print("\n### End of Section 6 ###")


'''
Section 10: Request Limits
'''
def section10():
    print("### Start of Section 10 ###\n")

    global apacheConfContent
    search_reg_exp = [r"^512$", r"^100$", r"^1024$", r"^102400$"]
    expected_values = ["512", "100", "1024", "102400"]
    directive_lines = ["LimitRequestLine 512", "LimitRequestFields 100", "LimitRequestFieldSize 1024",
                       "LimitRequestBody 102400"]
    directives = ["LimitRequestLine", "LimitRequestFields", "LimitRequestFieldSize", "LimitRequestBody"]
    found = [False, False, False, False]
    changed = [False, False, False, False]

    with open(apacheConfFile + ".new", "w+") as output_file:
        apacheConfContent = apacheConfContent.split('\n')

        for original_line in apacheConfContent:
            for i in range(0, 4):
                # If directive is in current line
                if directives[i] in original_line:
                    limit_req_line = original_line.split()
                    original_value = limit_req_line[1]

                    # Don't change the original value if it's correct.
                    if re.match(search_reg_exp[i], original_value):
                        found[i] = True
                        print(directives[i] + " already has a value of " + expected_values[i])

                    # Change the original value if it's incorrect.
                    else:
                        changed[i] = True
                        output_file.write(
                            directive_lines[i] + " # Corrected value from " + original_value + " to " +
                            expected_values[i] + "\n")  # Write the correct directive line.
                        print("Changed line: " + original_line.rstrip() + " --> " +
                                directive_lines[i])  # Print all changed lines.
                        original_line = ""  # Remove original line

            output_file.write(original_line + '\n')  # Restore the rest of the original config file.

        output_file.write("\n### Start of Added Directives for Section 10  of CIS Benchmark ###\n\n")
        for j, found_bool in enumerate(found):
            if not found_bool and not changed[j]:
                # If directive doesn't exist in config, write to last line of new config
                output_file.write(directive_lines[j] + "\n")
                print("Added line: " + directive_lines[j])  # Print all added lines.
        output_file.write("\n### End of Added Directives for Section 10  of CIS Benchmark ###\n")
        print(
            "\nAll changes are saved to " + apacheConfFile + ".new. To reflect all changes, manually rename this file to apache2.conf.")

    print("\n### End of Section 10 ###")


'''
Section 11: Enable SELinux to Restrict Apache Processes
'''
def section11():
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
            while not re.match(r"^y$", install_selinux) and not re.match(r"^n$", install_selinux):
                install_selinux = input("Install SELinux? (Y/N) ").rstrip().lower()
                if re.match(r"^y$", install_selinux):
                    print("Installing SELinux...\n")
                    subprocess.run("apt-get install selinux-basics selinux-utils policycoreutils -y >/dev/null 2>&1", shell=True)
                    subprocess.run("selinux-activate", shell=True) # Activate SELinux (set to permissive), subject to a reboot.
                    selinux_installed = True
                    print("After reboot, run \'setenforce 1' to temporarily set SELinux to enforcing. Note that this can cause stability issues in Ubuntu.")
                    print("Be warned that running \'selinux-config-enforcing\' will cause Ubuntu to hang on the next reboot\n")

                elif re.match(r"^n$", install_selinux) :
                    print("SELinux will not be installed.\n")
                    
                else:
                    continue
        
        # Prompts user to set SELinux to enforcing if mode is permissive, at least until the next reboot.
        if selinux_permissive:
            enforce_selinux = ""
            while not re.match(r"^y$", enforce_selinux) and not re.match(r"^n$", enforce_selinux):
                enforce_selinux = input("Set SELinux to enforcing? Note that this can cause stability issues in Ubuntu.(Y/N) ").rstrip().lower()
                if re.match(r"^y$", enforce_selinux):
                    subprocess.run("setenforce 1", shell=True)
                    print("SELinux set to enforcing.")
                    selinux_enforcing = True

                elif re.match(r"^n$", enforce_selinux) :
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
def section12():
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
            while not re.match(r"^y$", install_apparmor) and not re.match(r"^n$", install_apparmor):
                install_apparmor = input("AppArmor not installed. Install it? (Y/N) ").rstrip().lower()
                if re.match(r"^y$", install_apparmor):
                    print("Installing AppArmor...")
                    subprocess.run("apt-get update >/dev/null 2>&1 && apt-get install apparmor libapache2-mod-apparmor apparmor-utils snapd -y >/dev/null 2>&1", shell=True)
                    subprocess.run("/etc/init.d/apparmor start", shell=True) 
                    apparmor_installed = True

                elif re.match(r"^n$", install_apparmor):
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
                    while not re.match(r"^y$", download_apparmor_apache2_config_file) and not re.match(r"^n$", download_apparmor_apache2_config_file):
                        download_apparmor_apache2_config_file = input("AppArmor config file not found (required for audit). Download it? (Y/N) ").rstrip().lower()
                        if re.match(r"^y$", download_apparmor_apache2_config_file):
                            print("Downloading " + apparmor_apache2_config_file + "...")
                            subprocess.run("wget " + apparmor_apache2_config_file_download_link + " -O \"/etc/apparmor.d/usr.sbin.apache2\" >/dev/null 2>&1", shell=True)
                            subprocess.run("/etc/init.d/apparmor reload", shell=True)

                        elif re.match(r"^n$", download_apparmor_apache2_config_file) :
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


'''
Pre-requisites checks:

1. Check if root.
2. Section 1 of CIS Apache Benchmark.
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

        section1()

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
    remedy = remedy_check()
    prereq_check() # Includes Section 1

    # Goal: Determine web server configuration dir
    webSerDir = r'/etc/apache2'
    if not os.path.isdir(webSerDir):
        webSerDir = input('Enter Configuration Folder Location: ')
    
    apacheConfFile = '{}/apache2.conf'.format(webSerDir)
    if not os.path.isfile(apacheConfFile):
        apacheConfFile = input('Enter Main Configuration File Location: ')

    with open(apacheConfFile) as f:
        apacheConfContent = f.read()

    # Get Apache Environment Variables
    envVarPath = '{}/envvars'.format(webSerDir)
    while not os.path.isfile(envVarPath):
        envVarPath = input('Enter path to environment variable file: ')
    
    envVars = [i.split('export ')[1].split('=') for i in os.popen('cat {} | grep export'.format(envVarPath)).read().split('\n') if i and i[0] != '#']

    varDict = {}
    for var in envVars:
        if len(var) == 2:
            varDict[var[0]] = var[1]

    modCheck, modules = section2Audit()

    section2Analyze(modCheck, modules)

    section3Audit()

    section4Audit()

    section6Audit()

    section10()

    section11()

    section12()

    # Reload apache2 server if remedy were automatically ran
    if remedy:
        commandRun('service apache2 reload')
    else:
        print('Remember to reload Apache after applying the changes')
