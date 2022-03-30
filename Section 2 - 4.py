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
        print('Static Fix')
        print(staticMod)
        print()
    if len(dynamicMod):
        print('Dynamic Fix')
        print(dynamicMod)
        print()


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


# 2. Minimize Apache Modules (Analyze) - Not Done
def section2Analyze(modCheck, modules):
    print('MODULES ANALYSIS')
    if modCheck[0]:
        print('Only Enable the Necessary Files')
        staticMod, dynamicMod = filterMods(modules[0])
        print()

    if not modCheck[1]:
        print('Logging Module Disabled!!')

    if not modCheck[2]:
        print('WebDAV Modules Enabled!!')
        modDisable(modules[2])

    if not modCheck[3]:
        print('Status Module Enabled!!')
        modDisable(modules[3])

    if not modCheck[4]:
        print('AutoIndex Module Enabled!!')
        modDisable(modules[4])

    if not modCheck[5]:
        print('Proxy Modules Enabled!!')
        modDisable(modules[5])

    if not modCheck[6]:
        print('UserDir Module Enabled!!')
        modDisable(modules[6])

    if not modCheck[7]:
        print('Info Module Enabled!!')
        modDisable(modules[7])

    if not modCheck[8]:
        print('Outdated Auth Modules Enabled!!')
        modDisable(modules[8])


# 3. Principles, Permissions and Ownerships (Audit) - Not Done
def section3Audit():
    # Ensure Server is Ran as Non-Root

    # Ensure Apache User Account has Invalid Shell

    # Ensure Apache User is Locked

    # Ensure Apache Directories and Files are Owned by Root

    # Ensure Group is Set Correctly on Apache Directories and Files

    # Ensure Other Write Access on Apache Directories and Files is Restricted

    # Ensure Core Dump Directory is Secured

    # Ensure Lock File is Secured

    # Ensure PID File is Secured

    # Ensure ScoreBoard File is Secured

    # Ensure Group Write Access for Document Root Directories and Files is Proeprly Restricted

    # Ensure Access to Special Purpose Application Writable Directories is Properly Restricted
    
    pass


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
                change = True
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
            print(confChanges)
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

    modCheck, modules = section2Audit()
    section2Analyze(modCheck, modules)

    section4Audit()