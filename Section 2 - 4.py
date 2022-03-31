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
        
        os.system('cd {}'.format(pathToDis))
        os.system('{} --prefix={}'.format(configStr, prefix))
        os.system('make')
        os.system('make install')
        os.system('{}/bin/apachectl -k graceful-stop'.format(prefix))
        os.system('{}/bin/apachectl -k start'.format(prefix))

    if len(dynamicMod):
        print('Shared Modules to Disable')
        print(dynamicMod)
        disCom = 'a2dismod -f'
        for mod in dynamicMod:
            modName = mod.split('_module')[0]
            disCom += ' {}'.format(modName)

        os.system(disCom)
        os.system('service apache2 reload')


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
    print('MODULES ANALYSIS')
    modDisList = []
    if modCheck[0]:
        print('Only Enable the Necessary Files')
        staticMod, dynamicMod = filterMods(modules[0])
        print()

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
    
    # Ensure Server is Ran as Non-Root
    res = os.popen('grep -i ^User {}'.format(confFilePath)).read()
    userChk = res.split('User ')
    # GIVE FIX
    if userChk[0] == '#':
        print('User directive commented')
    else:
        user = userChk[1]

    res = os.popen('grep -i ^Group {}'.format(confFilePath)).read()
    # GIVE FIX
    if res[0] == '#':
        print('Group directive commented')

    if user.startswith('${'):
        user = varDict[user[2:-2]]

    res = os.popen('grep ^UID_MIN /etc/login.defs').read()
    uidMin = int(res.split()[1])

    res = os.popen('id {}'.format(user)).read()
    ids = res.split()
    uid = int(ids[0][4:].split('(')[0])

    # GIVE FIX
    if uid >= uidMin:
        print('Apache running as non-system account')

    # GIVE FIX
    if 'sudo' in ids[2]:
        print('Apache user has sudo privilege')

    # Ensure Apache User Account has Invalid Shell
    res = os.popen('grep {} /etc/passwd | grep /sbin/nologin'.format(user)).read()

    # GIVE FIX
    if not res:
        print('Apache user should not have a valid login shell')

    # Ensure Apache User is Locked
    res = os.popen('passwd -S {}'.format(user)).read()
    
    # GIVE FIX
    if res.split()[1] != 'L':
        print('Apache user not locked')

    # Ensure Apache Directories and Files are Owned by Root
    res = os.popen('find {} \! -user root -ls'.format(webSerDir)).read()

    # GIVE FIX
    if res:
        print('Found apache directories/files not owned by root')

    # Ensure Group is Set Correctly on Apache Directories and Files
    res = os.popen('find {} \! -group root -ls'.format(webSerDir)).read()

    # GIVE FIX
    if res:
        print('Found apache directories/files not in root group')

    # Ensure Other Write Access on Apache Directories and Files is Restricted
    res = os.popen('find -L {} \! -type l -perm /o=w -ls'.format(webSerDir)).read()

    # GIVE FIX
    if res:
        print('Found apache directories/files with other write access')

    # Ensure Core Dump Directory is Secured
    res = os.popen('cat {} | grep CoreDumpDirectory'.format(confFilePath)).read()
    
    # GIVE FIX
    if res:
        print('CoreDumpDirectory directive found in conf file')

    res = os.popen('find {} -prune \! -user root -ls'.format(varDict['APACHE_LOG_DIR'])).read()
    
    # GIVE FIX
    if res:
        print('Apache log folder not owned by root')

    res = os.popen('find {} -prune -perm o=rwx -ls'.format(varDict['APACHE_LOG_DIR'])).read()

    # GIVE FIX
    if res:
        print('Apache log directory accessible by others')

    # Ensure Lock File is Secured

    # Ensure PID File is Secured

    # Ensure ScoreBoard File is Secured

    # Ensure Group Write Access for Document Root Directories and Files is Proeprly Restricted

    # Ensure Access to Special Purpose Application Writable Directories is Properly Restricted


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

    if not requireFound:
        dirSplit.insert(-1, '/tRequire all denied')
        changed = True

    if not overrideFound:
        dirSplit.insert(-1, '/tAllowOverride None')
        changed = True

    for index in toRemove:
        dirSplit.pop(index)

    updatedField = '\n'.join(dirSplit)
    return updatedField, changed


def webContent(content):
    changed = False
    return changed


# 4. Apache Access Control (Audit) - Half Way
def section4Audit():
    # Getting Conf Files with Directives and Location Elements
    confPaths = []
    if os.path.isfile(r'{}/apache2.conf'.format(webSerDir)):
        confPaths.append(r'{}/apache2.conf'.format(webSerDir))

    print('Current Conf Files to be Anaylzed:')
    print(confPaths[0])

    chk = input('Are there any other conf files with Directory/Location elements? (Y/N) ')
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
        
        pattern = r'(<Directory[.\s\S]+?<\/Directory>)'
        res = re.finditer(pattern, content)

        confChanges = []

        for dir in res:
            dirField = dir.group()
            dirIndexes = dir.span()

            # Root Directory
            if dirField.split('\n')[0] in ['<Directory>', '<Directory />']:
                updatedField, changed = rootDirectory(dirField)
                if changed:
                    confChanges.append((dirIndexes, updatedField))

        newContent = []
        if len(confChanges):
            confName = confFile.split(r'/')[-1]
            print(confName)
            for change in reversed(confChanges):
                # Update Main Content String
                changeStr = content[change[0][0]:]
                content = content[:change[0][0]]

                # Update changeStr to new field/directive content
                newIndex = change[0][1] - change[0][0]
                updateStr = change[1] + changeStr[newIndex:]
                newContent.insert(0, updateStr)
        
            newContent.insert(0, content)

            with open('fixed-{}'.format(confName), 'w') as f:
                f.write(''.join(newContent))
        
        # if res:
        #     for dir in res:
        #         print(content.index(dir))
        #         if dir.split('\n')[0] in ['<Directory>', '<Directory />']:
        #             rootDirectory(dir)
        #         else:
        #             webContent(dir)


        # NEED TO LOOK INTO WHICH DIRECTIVES TO LOOK OUT FOR
        # Ensure Appropriate Access to Web Content is Allowed
        # Ensure OverRide is Disabled for All Directories


############################
# Section 3 Analysis Start #
############################
############################
#  Section 3 Analysis End  #
############################


############################
# Section 4 Analysis Start #
############################
############################
#  Section 4 Analysis End  #
############################

if __name__ == '__main__':
    # Goal: Determine web server configuration dir
    # To be changed to web server type chosen
    webSerDir = r'/etc/apache2'

    if (os.path.isdir(webSerDir)):
        print('Apache Folder Found')
    else:
        webSerDir = input('Enter Configuration Folder Location: ')

    # modCheck, modules = section2Audit()
    # section2Analyze(modCheck, modules)

    section3Audit()

    # section4Audit()