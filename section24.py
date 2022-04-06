import os
import re

'''
Will either run or print the command given based on the remedy flag
'''
def commandRun(command, remedy):
    if remedy:
        os.system('{} >/dev/null 2>&1'.format(command))
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
def modDisable(modList, remedy):
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

        commandRun(commandStr, remedy)

    if len(dynamicMod):
        print('Shared Modules to Disable')
        print(dynamicMod)
        disCom = 'a2dismod -f'
        for mod in dynamicMod:
            modName = mod.split('_module')[0]
            disCom += ' {}'.format(modName)

        commandRun(disCom, remedy)


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
def section2Analyze(modCheck, modules, remedy):
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
        modDisable(modDisList, remedy)

    print("\n### End of Section 2 ###")


'''
Section 3: Principles, Permissions and Ownerships
'''
def section3Audit(apacheConfContent, apacheConfFile, varDict, webSerDir, remedy):
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
        print('Ensure there is a User directive present in the {} file\n'.format(apacheConfFile))
    
    # ADD APACHE GROUP (MANUAL FIX) -Done
    res = os.popen('grep -i ^Group {}'.format(apacheConfFile)).read()
    if res:
        group = res.split('Group ')[1].replace('\n', '')
        chkList[1] = True
    else:
        print('No Apache group found')
        print('Ensure there is a Group directive present in the {} file\n'.format(apacheConfFile))

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
                commandRun('chsh -s /sbin/nologin {}'.format(user), remedy)

            # Ensure Apache User is Locked
            if os.popen('passwd -S {}'.format(user)).read().split()[1] != 'L':
                print('Apache user should be locked')
                commandRun('passwd -l {}'.format(user), remedy)

    # Ensure Apache Directories and Files are Owned by Root
    res = os.popen('find {} \! -user root'.format(webSerDir)).read()

    if res:
        print('Found apache directories/files not owned by root')
        commandRun('chown -R root {}'.format(webSerDir), remedy)

    # Ensure Group is Set Correctly on Apache Directories and Files
    res = os.popen('find {} \! -group root'.format(webSerDir)).read()

    if res:
        print('Found apache directories/files not in root group')
        commandRun('chgrp -R root {}'.format(webSerDir), remedy)

    # Ensure Other Write Access on Apache Directories and Files is Restricted
    res = os.popen('find -L {} \! -type l -perm /o=w'.format(webSerDir)).read()

    if res:
        print('Found apache directories/files with other write access')
        commandRun('chmod -R o-w {}'.format(webSerDir), remedy)

    # Ensure Group Write Access for Apache Directories and Files is Proeprly Restricted
    res = os.popen('find -L {} \! -type l -perm /g=w -ls'.format(webSerDir)).read()
    
    if res:
        print('Apache directories/files found with group write access')
        commandRun('chmod -R g-w {}'.format(webSerDir), remedy)

    # Ensure Core Dump Directory is Secured
    res = os.popen('grep -n CoreDumpDirectory {}'.format(apacheConfFile)).read().split('\n')[:-1]
    
    # Get the line number of the CoreDumpDirectory directive
    # Remove line from apache content
    if res:
        for line in res:
            lineNo = line.split(':', 1)[0]
            apacheConfContent.pop(int(lineNo) - 1)
        print('CoreDumpDirectory directive found in conf file')

    logDir = varDict['APACHE_LOG_DIR']
    res = os.popen('find {} -prune \! -user root'.format(logDir)).read()
    
    if res:
        print('Apache log directory not owned by root')
        commandRun('chown root {}'.format(logDir), remedy)

    res = os.popen('find {} -prune -perm /o=rwx'.format(logDir)).read()

    if res:
        print('Apache log directory accessible by others')
        commandRun('chmod o-rwx {}'.format(logDir), remedy)

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
                commandRun('chgrp {} {}'.format(group, logDir), remedy)

            # Ensure Group Write Access for Document Root Directories and Files is Properly Restricted
            res = os.popen('find -L {} -group {} -perm /g=w -ls'.format(docRoot, group)).read()
            
            if res:
                print('DocumentRoot directories/files found with group write access')
                commandRun('find -L {} -group {} -perm /g=w -print | xargs chmod g-w'.format(docRoot, group), remedy)

    # Ensure Lock File is Secured
    lockDir = varDict['APACHE_LOCK_DIR']
    
    # CHANGE LOCK DIRECTORY (MANUAL FIX)
    if docRoot in lockDir:
        print('Lock directory in document root: {}'.format(lockDir))
        print('Move/Modify directory to one outside of {}\n'.format(docRoot))

    res = os.popen('find {} -prune \! -user root'.format(lockDir)).read()

    if res:
        print('Apache lock directory not owned by root')
        commandRun('chown root:root {}'.format(lockDir), remedy)

    res = os.popen('find {} -prune -perm /o+w'.format(lockDir)).read()
    
    if res:
        print('Apache lock directory writable by others')
        commandRun('chmod o-w {}'.format(lockDir), remedy)

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
        commandRun('chown root:root {}'.format(pidDir), remedy)
    
    res = os.popen('find {} -prune -perm /o+w'.format(pidDir)).read()
    
    if res:
        print('Apache PID directory writable by others')
        commandRun('chmod o-w {}'.format(pidDir), remedy)

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
                commandRun('chown root:root {}'.format(scoreBoardDir), remedy)
            
            res = os.popen('find {} -prune -perm /o+w'.format(scoreBoardDir)).read()
            
            if res:
                print('ScoreBoardFile directory writable by others')
                commandRun('chmod o-w {}'.format(scoreBoardDir), remedy)

            res = os.popen('df -PT {} | tail -n +2 | awk "{{print $2}}" '.format(scoreBoardDir)).read().split('\n')[0]

            # MOVE DIRECTORY TO LOCAL HARD DRIVE (MANUAL FIX)
            if res == 'nfs':
                print('ScoreBoardFile directory is on an NFS mounted filesystem: {}'.format(scoreBoardDir))
                print('Move/Modify directory to a locally mounted file system')
 
    # Ensure Access to Special Purpose Application Writable Directories is Properly Restricted
    # Does not seem possible to do automatically, since we will require all the possible writable directories that the user will be having 

    print("\n### End of Section 3 ###")
    return apacheConfContent


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
def section4Audit(apacheConfContent, webSerDir, remedy):
    # Getting List of Conf Files for Web Content to Analyze
    #   - apache2.conf
    #   - sites-enabled
    #       - *.conf
    print("### Start of Section 4 ###\n")
    confPaths = ['SERVER_CONFIG_FILE']
    confPaths.extend(os.popen('ls {}/sites-enabled/*.conf'.format(webSerDir)).read().split('\n')[:-1])
    
    for confFile in confPaths:
        if confFile == 'SERVER_CONFIG_FILE':
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
    return apacheConfContent