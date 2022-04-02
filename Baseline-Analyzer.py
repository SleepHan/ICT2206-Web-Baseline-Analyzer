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

    print("\n### End of Section 2 ###\n")


'''
Section 3: Principles, Permissions and Ownerships
'''
def section3Audit():
    print("### Start of Section 3 ###\n")
    # Get Apache Environment Variables
    envVarPath = '{}/envvars'.format(webSerDir)
    while not os.path.isfile(envVarPath):
        envVarPath = input('Enter path to environment variable file: ')
    
    envVars = [i.split('export ')[1].split('=') for i in os.popen('cat {} | grep export'.format(envVarPath)).read().split('\n') if i and i[0] != '#']

    varDict = {}
    for var in envVars:
        if len(var) == 2:
            varDict[var[0]] = var[1]

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

    print("\n### End of Section 3 ###\n")


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
                confChanges.append((dirIndexes, updatedField))

        else:
            updatedField, changed = webContent(dirField, isDir)
            if changed:
                print(dirField)
                print(updatedField)
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
                confName = confFile.split(r'/')[-1]

                if remedy:
                    with open('{}.new'.format(confName), 'w') as f:
                        f.write(content)

    print("\n### End of Section 4 ###\n")


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

    print("\n### End of Section 10 ###\n")


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
    getenforce_error_code = ret.returncode

    if "Disabled" in getenforce_output:
        selinux_installed = True
        print("SELinux is disabled. Please enable it!")

    elif "Permissive" in getenforce_output:
        selinux_installed = True
        selinux_permissive = True
        print("SELinux is enabled in Permissive mode. Please enforce it with \'setenforce 1\'")
            

    elif "Enforcing" in getenforce_output:
        selinux_installed = True
        selinux_enforcing = True
        print("SELinux is enabled in Enforcing mode. No action is required.")
    
    if getenforce_error_code!=0: # If error from getenforce command.
        print("SELinux is not installed.")

    # Enable SELinux if disabled or install SELinux if not installed, but only if AppArmor is not running.
    if remedy:
        apparmor_status = os.system("systemctl is-active --quiet apparmor >/dev/null 2>&1")

        # If AppArmor is running, don't install SELinux.
        if apparmor_status == 0: 
            print("AppArmor is running. Aborting SELinux installation...")
        
        # Install and activate SELinux if not installed.
        elif not selinux_installed:
            install_selinux = ""
            while not re.match(r"^y$", install_selinux) and not re.match(r"^n$", install_selinux):
                install_selinux = input("Install SELinux? (Y/N) ").rstrip().lower()
                if re.match(r"^y$", install_selinux):
                    print("Installing SELinux and its dependencies...\n")
                    subprocess.run("apt-get install selinux-basics selinux-utils policycoreutils -y >/dev/null 2>&1", shell=True)
                    subprocess.run("selinux-activate", shell=True) # Activate SELinux (set to permissive), subject to a reboot.
                    #subprocess.run("selinux-config-enforcing", shell=True) # Enforce SELinux, subject to a reboot. Ubuntu won't boot if enforcing mode is set permanently.
                    selinux_installed = True
                    print("After reboot, run \'setenforce 1' to temporarily set SELinux to enforcing.")
                    print("Be warned that updating /etc/selinux/config to set \'selinux=enforcing\' will cause Ubuntu to hang on the next reboot, so use setenforce instead.\n")

                elif re.match(r"^n$", install_selinux) :
                    print("SELinux will not be installed.\n")
                    
                else:
                    continue

        
        # Set SELinux to enforcing if mode is permissive, at least until the next reboot.
        elif selinux_permissive:
            subprocess.run("setenforce 1", shell=True)
            print("SELinux set to enforcing.")

        # Activate SELinux if installed but disabled.
        elif not selinux_enforcing or not selinux_permissive:
            subprocess.run("selinux-activate", shell=True) # Activate SELinux (set to permissive), subject to a reboot.
            #subprocess.run("selinux-config-enforcing", shell=True) # Enforce SELinux, subject to a reboot. Ubuntu won't boot if enforcing mode is set permanently.
            print("After reboot, run \'setenforce\ 1' to temporarily set SELinux to enforcing.")
            print("Be warned that updating /etc/selinux/config to set \'selinux=enforcing\' will cause Ubuntu to hang on the next reboot, so use setenforce instead.\n")

    # If SELinux is installed, exit Section 11 since the rest of the section will involve SELinux.
    if not selinux_installed:
        print("Skipping Section 11...\n")
        print("\n### End of Section 11 ###\n")
        return

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
                httpd_boolean = httpd_boolean.strip()
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

    print("\n### End of Section 11 ###\n")


'''
Section 12: Enable AppArmor to Restrict Apache Processes. 
'''
def section12():
    print("### Start of Section 12 ###\n")

    apparmor_apache2_config_file = "/etc/apparmor.d/usr.sbin.apache2"
    apparmor_enabled = False
    selinux_installed = False

    ## 12.1  Ensure the AppArmor Framework Is Enabled
    command = "aa-status --enabled && echo Enabled"
    ret = subprocess.run(command, capture_output=True, shell=True)
    output = ret.stdout.decode()


    getenforce_error_code= os.system("getenforce >/dev/null 2>&1")

    if getenforce_error_code==0:
        print("SELinux is installed. Aborting AppArmor installation...")
        selinux_installed = True

    # Proceed only if SELinux is disabled or not installed.
    if not selinux_installed:
        print("SELinux is not installed. Proceeding with AppArmor installation...")
        # If AppArmor is disabled/not installed
        if not "Enabled" in output:
            install_apparmor = ""
            while not re.match(r"^y$", install_apparmor) and not re.match(r"^n$", install_apparmor):
                install_apparmor = input("AppArmor not enabled. Enable it? (Y/N) ").rstrip().lower()
                if re.match(r"^y$", install_apparmor):
                    print("Installing AppArmor and its dependencies...")
                    subprocess.run("apt-get update >/dev/null 2>&1 && apt-get install apparmor libapache2-mod-apparmor apparmor-utils snapd -y >/dev/null 2>&1", shell=True)
                    subprocess.run("/etc/init.d/apparmor start", shell=True) 
                    apparmor_enabled = True

                elif re.match(r"^n$", install_apparmor):
                    print("AppArmor will not be enabled.\n")
                else:
                    continue
        
        # If AppArmor is already enabled/installed
        else:
            apparmor_enabled = True

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
                        download_apparmor_apache2_config_file = input("AppArmor config file not found. Download it? (Y/N) ").rstrip().lower()
                        if re.match(r"^y$", download_apparmor_apache2_config_file):
                            print("Downloading " + apparmor_apache2_config_file + "...")
                            subprocess.run("wget " + apparmor_apache2_config_file_download_link + " -O \"/etc/apparmor.d/usr.sbin.apache2\" >/dev/null 2>&1", shell=True)
                            subprocess.run("/etc/init.d/apparmor reload", shell=True)
                            apparmor_enabled = True

                        elif re.match(r"^n$", download_apparmor_apache2_config_file) :
                            print("Default AppArmor Apache configuration file downloaded.\n")
                        else:
                            continue

        
        # If AppArmor is not enabled or doesn't have dependencies installed, exit Section 12 since the rest of the section will involve AppArmor.
        if not apparmor_enabled:
            print("Skipping Section 12...")
            print("\n### End of Section 12 ###\n")
            return

        # 12.2 Ensure the Apache AppArmor Profile Is Configured Properly.
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
        
        
        # Section 12.3 Ensure Apache AppArmor Profile is in Enforce Mode.

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

    print("\n### End of Section 12 ###\n")


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
        print("Not root. Running as root...")
        subprocess.run("sudo bash", shell=True) 
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

    modCheck, modules = section2Audit()
    section2Analyze(modCheck, modules)

    section3Audit()

    section4Audit()

    section10()

    section11()

    section12()

    # Reload apache2 server if remedy were automatically ran
    if remedy:
        commandRun('service apache2 reload')
    else:
        print('Remember to reload apache after applying the changes')