from importlib.resources import path
import os
import re
import sys
import subprocess
import pathlib


'''
Will either run or print the command given based on the remedy flag
'''
def commandRun(command, remedy):
    if remedy:
        os.system(command)
    else:
        print('Run Command: {}'.format(command))
        print()


'''
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


def checkVirtualHost(pattern, errorLogFile, errorLogFaci, customLog, logFormatStrings, apacheConfContent):
    content = apacheConfContent
    res = re.finditer(pattern, content)

    confChanges = []
    change = False
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
        change = True

    return apacheConfContent, change


'''
Section 6: Operations - Logging, Monitoring and Maintenance
'''
def section6Audit(webSerDir, apacheConfFile, varDict, remedy):
    print("### Start of Section 6 ###\n")
    apacheConfContentSplit = open(apacheConfFile).read().split('\n')
    logLevel = False
    contentChange = False
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
                    contentChange = True
                    
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
                        contentChange = True

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
                    contentChange = True

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
                    contentChange = True
            elif all (token in line for token in logFormatTokens):
                customLog = line
            else:
                apacheConfContentSplit.pop(customIndex)
                contentChange = True

    apacheConfContent = '\n'.join(apacheConfContentSplit)

    if not logLevel:
        print('LogLevel directive not found. Adding directive...')
        print('LogLevel notice core:info')
        apacheConfContent += '\nLogLevel notice core:info'
        contentChange = True

    if not errorLogFile:
        print('ErrorLog directive to log file not found. Adding directive...')
        print('ErrorLog ${APACHE_LOG_DIR}/error.log\n')
        errorLogFile = '\nErrorLog ${APACHE_LOG_DIR}//error.log'
        apacheConfContent += errorLogFile
        contentChange = True

    if not errorLogFaci:
        print('ErrorLog directive to syslog facility not found. Adding directive...')
        print('ErrorLog syslog:local7\n')
        errorLogFaci = '\nErrorLog syslog:local7'
        apacheConfContent += errorLogFaci
        contentChange = True
    
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
        contentChange = True
        print(customLog)

    print('Updating Virtual Host Directives\n')
    pattern = '(\n<VirtualHost[.\s\S]+?<\/VirtualHost>)'
    apacheConfContent, contentChange = checkVirtualHost(pattern, errorLogFile, errorLogFaci, customLog, logFormatStrings, apacheConfContent)

    # 6.4 Ensure Log Storage and Rotation is Configured Correctly
    if logRotateType == '1':
        with open('/etc/logrotate.d/apache2') as f:
            content = f.readlines()
        linesToLookFor = ['missingok', 'notifempty', 'sharedscripts']
        changed = False
        
        for line in content:
            conf = line.split()
            if len(conf) == 1 and conf[0] in linesToLookFor:
                linesToLookFor.remove(conf[0])
        
        if len(linesToLookFor):
            for line in linesToLookFor:
                content.insert(1, '    {}\n'.format(line))

        if changed:
            if remedy:
                with open('/etc/logrotate.d/apache2', 'w') as f:
                    f.write(''.join(content))
            else:
                pathlib.Path('conf/etc/logrotate.d').mkdir(parents=True, exist_ok=True)
                with open('conf/etc/logrotate.d/apache2', 'w') as f:
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
            if remedy:
                with open('/etc/logrotate.conf', 'w') as f:
                    f.write(''.join (content))
            else:
                pathlib.Path('conf/etc').mkdir(parents=True, exist_ok=True)
                with open('conf/etc/logrotate.conf', 'w') as f:
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
                print('Run command: apt-get install libapache2-mod-security2 -y\n')
        else:
            installed = True

        # Enable module
        if installed:
            commandRun('a2enmod security2', remedy)
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
    if os.path.isdir('/etc/apache2/modsecurity.d'):
        res = os.popen('ls /etc/apache2/modsecurity.d | grep owasp-modsecurity-crs-*').read()
    else:
        res = False
        
    running = False

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
            running = True
        else:
            print('OWASP ModSecurity CRS not installed')
            print('Run these commands to install/download OWASP ModSecurity CRS')
            print(commandLine)

            print('\nAdd the following lines to the mods-enabled/security2.conf file')
            print('Include modsecurity.d/owasp-modsecurity-crs-3.2.0/crs-setup.conf')
            print('Include modsecurity.d/owasp-modsecurity-crs-3.2.0//rules/*.conf')

            print('\nservice apache2 reload')
    else:
        running = True

    if running == True:
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

    if contentChange:
        if remedy:
            with open(apacheConfFile, 'w') as f:
                f.write(apacheConfContent)
        else:
            pathlib.Path('conf{}'.format(apacheConfFile.rsplit('/', 1)[0])).mkdir(parents=True, exist_ok=True)
            with open('conf{}'.format(apacheConfFile), 'w') as f:
                f.write('\n'.join(apacheConfContent))
    print("\n### End of Section 6 ###")