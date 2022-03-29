import os
import re

# Goal: Determine web server configuration dir
# To be changed to web server type chosen
webSerDir = r'/etc/apache2'

if (os.path.isdir(webSerDir)):
    print('Apache Folder Found')
else:
    webSerDir = input('Enter Configuration Folder Location: ')


# Separates Modules to Statically or Dynamically Loaded
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


#########################
# Section 2 Audit Start #
#########################
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

print('STATIC MODULES ANALYSIS')
if modCheck[0]:
    print('Only Enable the Necessary Files')
    print(modules[0])
    print('\n')

if not modCheck[1]:
    print('Logging Module Disabled!!\n')

if not modCheck[2]:
    print('WebDAV Modules Enabled!!\n')

if not modCheck[3]:
    print('Status Module Enabled!!\n')

if not modCheck[4]:
    print('AutoIndex Module Enabled!!\n')

if not modCheck[5]:
    print('Proxy Modules Enabled!!\n')

if not modCheck[6]:
    print('UserDir Module Enabled!!\n')

if not modCheck[7]:
    print('Info Module Enabled!!\n')

if not modCheck[8]:
    print('Outdated Auth Modules Enabled!!\n')
#########################
#  Section 2 Audit End  #
#########################
