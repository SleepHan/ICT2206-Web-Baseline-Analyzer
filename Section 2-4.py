import os
import re

# Separates modules to statically or dynamically loaded
def filterMods(modList):
    staticMods = []
    dynamicMods = []

    if len(modList):
        for mod in modList:
            if mod:
                modName = mod[1:-9]
                modType = mod[-7:-1]
                if modType == 'static':
                    staticMods.append(modName)
                else:
                    dynamicMods.append(modName)

    return staticMods, dynamicMods


# Will either run command or print
def commandRun(command):
    if runFix:
        os.system(command)
    else:
        print(command)


# Gives the appropriate fix for statically or dynamically loaded modules
def modDisable(modList):
    staticMod, dynamicMod = filterMods(modList)
    if len(staticMod):
        print('Static Modules to Disable')
        pathToDis = input('Enter the path to your Apache source folder: ')
        prefix = input('Enter location of server installation: ')
        configStr = './configure'
        for mod in staticMod:
            modName = mod.split('_module')[0].replace('_', '-')
            configStr += ' --disable-{}'.format(modName)
        
        commandRun('cd {}'.format(pathToDis))
        commandRun('{} --prefix={}'.format(configStr, prefix))
        commandRun('make')
        commandRun('make install')
        commandRun('{}/bin/apachectl -k graceful-stop'.format(prefix))
        commandRun('{}/bin/apachectl -k start'.format(prefix))

    if len(dynamicMod):
        print('Shared Modules to Disable')
        print(dynamicMod)
        disCom = 'a2dismod -f'
        for mod in dynamicMod:
            modName = mod.split('_module')[0]
            disCom += ' {}'.format(modName)

        commandRun(disCom)
        commandRun('service apache2 reload')


# 2. Minimize Apache Modules (Audit)
def section2Audit():
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


# 2. Minimize Apache Modules (Analyze) - Left 2.1
def section2Analyze(modCheck, modules):
    modDisList = []
    if modCheck[0]:
        print('Only Enable the Necessary Files')
        print(modules[0])

    if not modCheck[1]:
        print('Logging Module Disabled!!')

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


# 3. Principles, Permissions and Ownerships (Audit) - Not Done
def section3Audit():
    # Get Apache Environment Variables
    envVarPath = '{}/envvars'.format(webSerDir)
    while not os.path.isfile(envVarPath):
        envVarPath = input('Enter path to environment variable file: ')
    
    envVars = [i.split('export ')[1].split('=') for i in os.popen('cat {} | grep export'.format(envVarPath)).read().split('\n') if i and i[0] != '#']

    varDict = {}
    for var in envVars:
        if len(var) == 2:
            varDict[var[0]] = var[1]

    # Get Apache Configuration File
    confFilePath = '{}/apache2.conf'.format(webSerDir)
    while not os.path.isfile(confFilePath):
        confFilePath = input('Enter path to apache configuration file: ')

    # [User Exist, Group Exist]
    chkList = [False, False]

    # ADD APACHE USER (MANUAL FIX)
    res = os.popen('grep -i ^User {}'.format(confFilePath)).read()
    if res:
        user = res.split('User ')[1].replace('\n', '')
        chkList[0] = True
    else:
        print('No Apache User found')
    
    # ADD APACHE GROUP (MANUAL FIX)
    res = os.popen('grep -i ^Group {}'.format(confFilePath)).read()
    if res:
        group = res.split('Group ')[1].replace('\n', '')
        chkList[1] = True
    else:
        print('No Apache group found')

    if chkList[0]:
        if user.startswith('${'):
            user = varDict[user[2:-1]]

        res = os.popen('grep ^UID_MIN /etc/login.defs').read()
        uidMin = int(res.split()[1])

        res = os.popen('id {}'.format(user)).read()
        ids = res.split()
        uid = int(ids[0][4:].split('(')[0])

        # CREATE NEW USER (MANUAL FIX)
        if uid >= uidMin:
            print('Apache running as non-system account')

        # REMOVE FROM SUDOER GROUP (MANUAL FIX)
        elif 'sudo' in ids[2]:
            print('Apache user has sudo privilege')

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
    docRoot = os.popen('grep -i DocumentRoot {}/sites-available/000-default.conf'.format(webSerDir)).read().split()[-1]
    res = os.popen('grep -n CoreDumpDirectory {}'.format(confFilePath)).read().split('\n')[:-1]
    
    # Get the line number of the CoreDumpDirectory directive
    # Remove line using sed
    if res:
        for line in res:
            lineNo = line.split(':', 1)[0]
            commandRun("sed -i '{}d' {}".format(lineNo, confFilePath))
        print('CoreDumpDirectory directive found in conf file')

    logDir = varDict['APACHE_LOG_DIR']
    res = os.popen('find {} -prune \! -user root'.format(logDir)).read()
    
    if res:
        print('Apache log directory not owned by root')
        commandRun('chown root {}'.format(logDir))

    if chkList[1]:
        res = os.popen('find {} -prune \! -group {}'.format(logDir, group))
        if res:
            print('Apache log directory not owned by {} group'.format(group))
            commandRun('chgrp {} {}'.format(group, logDir))

        # Ensure Group Write Access for Document Root Directories and Files is Properly Restricted
        res = os.popen('find -L {} -group {} -perm /g=w -ls'.format(docRoot, group)).read()
        
        if res:
            print('DocumentRoot directories/files found with group write access')
            commandRun('find -L {} -group {} -perm /g=w -print | xargs chmod g-w'.format(docRoot, group))

    res = os.popen('find {} -prune -perm /o=rwx'.format(logDir)).read()

    if res:
        print('Apache log directory accessible by others')
        commandRun('chmod o-rwx {}'.format(logDir))

    # Ensure Lock File is Secured
    lockDir = varDict['APACHE_LOCK_DIR']

    # CHANGE LOCK DIRECTORY (MANUAL FIX)
    if docRoot in lockDir:
        print('Lock directory in document root')

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
        print('ScoreBoardFile directory is on an NFS mounted filesystem')
        
    # Ensure PID File is Secured
    res = os.popen('grep "PidFile " {}'.format(confFilePath)).read()
    pidFilePath = res.split(' ', 1)[1]
    
    if pidFilePath.startswith('${'):
        pidFilePath = varDict[pidFilePath[2:-2]]

    pidDir = pidFilePath.rsplit('/', 1)[0]

    # CHANGE PID DIRECTORY (MANUAL FIX)
    if docRoot in pidDir:
        print('PID directory in document root')

    res = os.popen('find {} -prune \! -user root'.format(pidDir)).read()

    if res:
        print('Apache PID directory not owned by root')
        commandRun('chown root:root {}'.format(pidDir))
    
    res = os.popen('find {} -prune -perm /o+w'.format(pidDir)).read()
    
    if res:
        print('Apache PID directory writable by others')
        commandRun('chmod o-w {}'.format(pidDir))

    # Ensure ScoreBoard File is Secured
    confPaths = []
    if os.path.isfile(r'{}/apache2.conf'.format(webSerDir)):
        confPaths.append(r'{}/apache2.conf'.format(webSerDir))

    print('Current Conf Files to be Anaylzed:')
    print(confPaths[0])

    chk = input('Are there any other conf files with the ScoreBoard directive? (Y/N) ')
    if chk.lower() == 'y':
        newConf = input('Enter conf file path (Enter "end" when done): ')
        while newConf.lower() != 'end':
            if os.path.isfile(newConf):
                confPaths.append(newConf)
            else:
                print('File not found')

            newConf = input('Enter conf file path (Enter "end" when done): ')

    for conf in confPaths:
        res = os.popen('grep ScoreBoardFile {}'.format(conf)).read().split('\n')[:-1]

        if res:
            for score in res:
                scoreBoardDir = score.split(' ', 1).rsplit('/', 1)

                # CHANGE SCOREBOARD DIRECTORY (MANUAL FIX)
                if docRoot in scoreBoardDir:
                    print('ScoreBoardFile directory in document root')

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
                    print('ScoreBoardFile directory is on an NFS mounted filesystem')

    

   
    # KIV
    # Ensure Access to Special Purpose Application Writable Directories is Properly Restricted
    res = os.popen('find {} -prune \! -user {}'.format(docRoot, varDict['APACHE_RUN_USER'])).read()

    # GIVE FIX
    if res:
        print('Document Root not owned by Run User')
    
    
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


# Checks for the appropriate access control for the OS root directory
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
    

# Checks for the appropriate access control for directives
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


# Updates the configuration file content
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


# Removes any instances of the AllowOverrideList directive from the configuration content
def rmAllowOverrideList(confContent):
    contentSplit = confContent.split('\n')
    toRemove = []
    for index in range(len(contentSplit)):
        line = contentSplit[index]
        if line:
            if line.split()[0] == 'AllowOverrideList':
                toRemove.append(index)

    toRemove.reverse()
    for index in toRemove:
        contentSplit.pop(index)

    return '\n'.join(contentSplit)


# 4. Apache Access Control (Audit) - Half Way
def section4Audit():
    # Getting Conf Files with Directives and Location Elements
    confPaths = []
    if os.path.isfile(r'{}/apache2.conf'.format(webSerDir)):
        confPaths.append(r'{}/apache2.conf'.format(webSerDir))

    print('Current Conf Files to be Anaylzed:')
    print(confPaths[0])

    chk = input('Are there any other conf files with Web Content elements? (Y/N) ')
    if chk.lower() == 'y':
        newConf = input('Enter conf file path (Enter "end" when done): ')
        while newConf.lower() != 'end':
            if os.path.isfile(newConf):
                confPaths.append(newConf)
            else:
                print('File not found')

            newConf = input('Enter conf file path (Enter "end" when done): ')

    
    for confFile in confPaths:
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
            confName = confFile.split(r'/')[-1]

            if runFix:
                with open('fixed-{}'.format(confName), 'w') as f:
                    f.write(content)


if __name__ == '__main__':
    runFix = False

    # Goal: Determine web server configuration dir
    webSerDir = r'/etc/apache2'

    if (os.path.isdir(webSerDir)):
        print('Apache Folder Found')
    else:
        webSerDir = input('Enter Configuration Folder Location: ')

    modCheck, modules = section2Audit()
    section2Analyze(modCheck, modules)

    section3Audit()

    section4Audit()