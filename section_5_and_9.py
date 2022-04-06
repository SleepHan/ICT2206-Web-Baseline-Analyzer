from nis import match
import re
import os
import subprocess
from prettytable import PrettyTable



# 5.1
def ensure_access_to_os_root_directory(verbose=True):
    # Check Boolean
    check_1_bool = False
    check_2_bool = True
    title = "5.1 Ensure Options for the OS Root Directory Are Restricted"
    file_location = "/etc/apache2/apache2.conf"
    flagged_configurations = []
    # Read the httpd.conf file
    
    rule_1_solution = "Add a single Options directive\nif there is none.\n\nElse, set the value\nfor Options to None"
    # rule_2 = "Ensure there are no\nAllow or Deny directives\nin the root <Directory> Element"
    
    rule_1 = "Ensure there is a\nsingle options directive\nwith the value of None"
    # rule_2_solution = "Remove any Deny and\nAllow directives from\nthe root <Directory> element"
    
    regex_pattern_for_root = re.compile("<Directory\s/>\n[A-Za-z\s+,</>]+?\n</Directory>{1}")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()

    check_1_statements = []
    # check_2_statements = []

    # Find all of the entries that is Root Directory related
    for match in re.findall(regex_pattern_for_root, lines):
        # Check if there is a single require directive with the value of all denied
        contains_all_denied = re.compile("Options None")

        if re.findall(contains_all_denied, match):
            check_1_bool = True
        
        if not re.findall(contains_all_denied, match) and check_1_bool is False:
            check_1_statements.append(match)  
        # contains_allow_or_deny = r"Allow\W|Deny\W"
    
        # if re.findall(contains_allow_or_deny, match):
        #     check_2_bool = False

    # if check_1_bool is False or check_2_bool is False: 
    if check_1_bool is False: 
        
       
            
        # if re.findall(contains_allow_or_deny, match) and check_2_bool is False: 
        #     check_2_statements.append(match)   

        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            flagged_out_table.min_width["Solution"]=20
            flagged_out_table.min_width["Configuration"]=20
            flagged_out_table.max_width["Solution"]=40
            flagged_out_table.max_width["Configuration"]=40
            for i in check_1_statements:
                results = re.sub("Options\W(?!None)[A-Za-z+,]*\n", "Options None\n", i)
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 
   
            print(flagged_out_table)
    else:
        if verbose:
            print(title + f' (passed)')
        

# 5.2
def ensure_options_for_web_root_directory_are_restricted(verbose=True):
    title = "5.2 Ensure Options for the Web Root Directory Are Restricted"
    file_location = "/etc/apache2/apache2.conf"
    check_1_bool = True
    check_1_statements =[]
    rule_1 = "Search the Apache configuration\nfiles (httpd.conf and any\nincluded configuration files) to\nfind the document root <Directory>\nelements and ensure there is\na single Options directive with the\nvalue of None or Multiviews."
    regex_pattern_for_root = re.compile("<Directory\s.*>\n[A-Za-z\s+,</>]+?\n</Directory>{1}")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    for match in re.findall(regex_pattern_for_root, lines):
        # Check if there is a single require directive with the value of all denied
        regex_verifier = re.compile("Options\sNone|Multiview")
        
        if not re.findall(regex_verifier, match):
            check_1_bool = False
            check_1_statements.append(match)
            
            
    if check_1_bool is False: 
        # if re.findall(contains_allow_or_deny, match) and check_2_bool is False: 
        #     check_2_statements.append(match)   
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            for i in check_1_statements:
                results = re.sub("Options\W(?!None)[A-Za-z+,]*\n", "Options [None|Multiview]\n", i)
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 
   
            print(flagged_out_table)
    else:
        if verbose:
            print(title + f' (passed)')

# 5.3 
def ensure_options_for_other_directories_are_minimized(verbose=True):
    title = "5.3 Ensure options for other directories are minimized"
    # file_location = "/etc/apache2/apache2.conf.test"
    file_location = "/etc/apache2/apache2.conf"
    check_1_bool = False
    check_1_statements =[]
    rule_1 = "Search the Apache configuration files\n(httpd.conf and any included configuration files)\nto find the all Directory elements and\nensure that the Options directives\ndo not enable Includes."
    regex_pattern_for_root = re.compile("<Directory\s.*>\n[A-Za-z\s+,</>]+?\n</Directory>{1}")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    for match in re.findall(regex_pattern_for_root, lines):
        # Check if there is a single require directive with the value of all denied
        regex_verifier = re.compile("Options\sIncludes")
        
        if re.findall(regex_verifier, match):
            check_1_bool = True
            check_1_statements.append(match)
            
            
    if check_1_bool is True: 
        # if re.findall(contains_allow_or_deny, match) and check_2_bool is False: 
        #     check_2_statements.append(match)   
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            for i in check_1_statements:
                results = re.sub("Options\W(?!None)[A-Za-z+,]*\n", "Options [Multiviews|ExecCGI|FollowSymLinks\n|SymLinksIfOwnerMatch|Includes|IncludesNoExec|Indexes]\n", i)
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 
   
            print(flagged_out_table)
    else:
        if verbose:
            print(title + f' (passed)')
       
# 5.4 (Not sure)
def ensure_default_html_content_is_removed(verbose=True):
    pass
    

# 5.5 
def ensure_printenv_script_is_removed(verbose=True):
    title = "5.5 Ensure the Default CGI Content printenv Script is removed"
    file_location = "/usr/lib/cgi-bin"
    value = os.listdir(file_location)
    check_1_bool = True
    check_1_statements = []
    rule_1 = "Ensure the printenv CGI is\nnot installed in any configured cgi-bin directory"
    file_to_flag = "printenv"
    for i in value:
        if file_to_flag in i:
            check_1_bool = False
            check_1_statements.append(i)
    if check_1_bool is False: 
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            results = "Run the following Command\n\nrm {}/printenv".format(file_location)
            for i in check_1_statements:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose: 
           print(title + f' (passed)') 

# 5.6 
def ensure_testcgi_script_is_removed(verbose=True):
    title = "5.6 Ensure the Default CGI Content test-cgi Script is removed"
    file_location = "/usr/lib/cgi-bin"
    value = os.listdir(file_location)
    check_1_bool = True
    check_1_statements = []
    rule_1 = "Ensure the test-cgi is\nnot installed in any configured cgi-bin directory"
    file_to_flag = "test-cgi"
    for i in value:
        if file_to_flag in i:
            check_1_bool = False
            check_1_statements.append(i)
    if check_1_bool is False: 
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            results = "Run the following Command\n\nrm {}/printenv".format(file_location)
            for i in check_1_statements:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose: 
           print(title + f' (passed)') 

# 5.7 
def ensure_http_request_methods_are_restricted(verbose=True):
    title = "5.7 Ensure HTTP Request Methods are restricted"
    # file_location = "/etc/apache2/apache2.conf.test"
    file_location = "/etc/apache2/apache2.conf"
    check_1_bool = True 
    check_1_statements =[]
    check_2_bool = True 
    check_2_statements =[]
    rule_1 = "Ensure there is a single\nRequire directive with\nthe value of all denied"
    rule_2 = "Ensure that there are no Allow or Deny\ndirectives in the root element."
    regex_pattern_for_root = re.compile("<Directory\s/(?!>)[a-zA-Z/]*>\n[A-Za-z\s+,</>]+?\n</Directory>{1}")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
  
    for match in re.findall(regex_pattern_for_root, lines):
        # Check if there is a single require directive with the value of all denied
        regex_verifier = re.compile("Require all denied") 
        if not re.findall(regex_verifier, match):
            check_1_bool = False   
            check_1_statements.append(match)
        
        regex_verifier_2 = re.compile("Allow\W|Deny\W")
        if re.findall(regex_verifier_2, match): 
            check_2_bool = False
            check_2_statements.append(match)
        
        results = """
Modify the File to Limit HTTP Methods using the LimitExcept\n
<Directory "path/path/path">
. . .
        # Limit HTTP methods
        <LimitExcept GET POST OPTIONS>
        Require all denied
        </LimitExcept>
</Directory>
"""
    if check_1_bool is False: 
     
        if verbose:
           
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            for i in check_1_statements:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 
   
            print(flagged_out_table)
    
    if check_2_bool is False: 
        if verbose:
           
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            for i in check_2_statements:
                flagged_out_table.add_row([rule_2, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 
   
            print(flagged_out_table)
 
            
    if check_1_bool is True and check_2_bool is True:
        if verbose:
            print(title + f' (passed)')

# 5.8
def ensure_http_trace_method_is_disabled(verbose=True):
    title = "5.8 Enable the HTTP Trace Method is disabled"
    # file_location = "/etc/apache2/apache2.conf.test"
    file_location = "/etc/apache2/apache2.conf"
    check_1_bool = True 
    rule_1 = "Locate the Apache configuration files\nand included configuration files\nand verify there is a single TraceEnable directive\nconfigured with a value of off."
    regex_pattern_for_root = re.compile("TraceEnable Off")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    if not re.findall(regex_pattern_for_root, lines):
        # Check if there is a single require directive with the value of all denied
            check_1_bool = False   
        
     
    results = """
Modify the File to Include\n\n
TraceEnable Off
"""
    if check_1_bool is False: 
     
        if verbose:
           
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            flagged_out_table.add_row([rule_1, file_location , results , "Configuration is either not set\nor has TraceEnable On" ])
            flagged_out_table.add_row(["","","",""])
            flagged_out_table.add_row(["","","",""])
            flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 
   
            print(flagged_out_table)
    else:
        if verbose:
            print(title + f' (passed)')


# 5.9 (unsure)
def ensure_old_http_protocol_versions_are_disallowed(verbose=True):
    pass        

# 5.10 
def ensure_access_to_ht_files_is_restricted(verbose=True):
    title = "5.10 Ensure Access to .ht* is restricted"
    file_location = "/etc/apache2/apache2.conf"
    check_1_bool = True 
    check_1_statement = []
    rule_1 = "Verify that a FilesMatch directive similar\nto the one below is present\nin the apache configuration and not commented out.\nThe deprecated Deny from All directive may be\nused instead of the Require directive."
    regex_pattern_for_root = re.compile("<FilesMatch \"\^\\\.ht\">[A-Za-z\n\t].+\n</FilesMatch>")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
  
    for match in re.findall(regex_pattern_for_root, lines):
        # Check if there is a single require directive with the value of all denied
            regex_verifier = re.compile("Require all denied\W")
            if not re.findall(regex_verifier, match):
                check_1_bool = False
                check_1_statement.append(match)
     
    results = """Modify the File to Include\n
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch> 
"""
    if check_1_bool is False: 
     
        if verbose:
           
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            for i in check_1_statement:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 
   
            print(flagged_out_table)
    else:
        if verbose:
            print(title + f' (passed)')
    
    
# 5.11 
def ensure_access_to_inappropriate_file_extensions_is_restricted(verbose=True):
    dir = "/var/www"
    os.chdir(dir)
    value = subprocess.Popen("find -type f -name '*.*' | awk -F. '{print $NF}' | sort -u", shell=True,stdout=subprocess.PIPE).stdout
    extensions = []
    for i in value.readlines():
        i_in_string = i.decode('utf-8')
        extensions.append(i_in_string.strip("\n"))
    
    title = "5.11 Ensure Access to Inappropriate File Extension is restricted"
    file_location = "/etc/apache2/apache2.conf"
    check_1_bool = False 
    check_1_statement = []
    

    rule_1 = "Add the FilesMatch directive\nthat denies all fies and\nonly allow access to files that are approved."
    regex_pattern_for_root = re.compile("<FilesMatch \"\^\.\*\$\">\n\s.*Require all denied\s*\n</FilesMatch>")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    # Means that they have the Second Rule 
    if re.findall(regex_pattern_for_root, lines):
        check_1_bool = True

    results = """1) Modify the File to Include\n\n
# Block all files by default, unless specifically allowed.
<FilesMatch "^.*$">
 Require all denied
</FilesMatch>

2) Modify and include a Whitelist\n\n
# Allow files with specifically approved file extensions
# We retrived the following extensions from {}
# {} 
<FilesMatch "^.*\.(css|html?|js)$">
 Require all granted
</FilesMatch>
""".format(dir, extensions)
    
    if check_1_bool is False: 
    # if re.findall(contains_allow_or_deny, match) and check_2_bool is False: 
    #     check_2_statements.append(match)   
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            flagged_out_table.add_row([rule_1, file_location , results , "Missing Block all files by\ndefualt rule or it\nis misconfigured" ])
            flagged_out_table.add_row(["","","",""])
            flagged_out_table.add_row(["","","",""])
            flagged_out_table.add_row(["","","",""])
            
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose:
            print(title + f' (passed)')

# 5.12 (unsure)

# 5.13 
def ensure_ip_address_for_listening_for_requests_are_specified(verbose=True):
   
    title = "5.13 Ensure IP Address for listening for requests are specified"
    file_location = "/etc/apache2/ports.conf"
    check_1_bool = False 
    check_1_statement = []
    

    rule_1 = "Verify that no Listen directives are\nin the Apache configuration file with no\nIP address specified,\nor with an IP address of all zeros."
    regex_pattern_for_root = re.compile("Listen\s.*")

    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    # If they have listen
    for matches in re.findall(regex_pattern_for_root, lines):
        check_1_bool = False
        check_1_statement.append(matches)
    

    results = """Requires Manual Check\n\n
Modify the Listen directives in the Apache\nconfiguration file to have explicit IP 
addresses\naccording to the intended usage.\n

Multiple Listen directives may be\nspecified for each IP address & Port.\n
"""
    
    if check_1_bool is False: 
    # if re.findall(contains_allow_or_deny, match) and check_2_bool is False: 
    #     check_2_statements.append(match)   
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            if check_1_statement is []: 
                flagged_out_table.add_row([rule_1, file_location , results , "No Listen Statement could be found" ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
            else:
                for i in check_1_statement:
                    flagged_out_table.add_row([rule_1, file_location , results , i ])
                    flagged_out_table.add_row(["","","",""])
                    flagged_out_table.add_row(["","","",""])
                    flagged_out_table.add_row(["","","",""])
            
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose:
            print(title + f' (passed)')
     
# 9.1 
def ensure_the_timeout_is_set_to_10_or_less(verbose=True): 
    title = "9.1 Ensure the Timeout is set to 10 or less"
    file_location = "/etc/apache2/apache2.conf"
    timeout_found = False
    check_1_bool = False
    check_1_statements = []
    rule_1 = "Verify that the Timeout directive is specified in the Apache\nconfiguration files to have a value of 10 seconds or shorter."
    regex_pattern_for_root = re.compile(".*Timeout\s.*")
    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    # If they have listen
    for matches in re.findall(regex_pattern_for_root, lines):
        para_check = matches[0:7]
        if "Timeout" == para_check:
            timeout_found = True
            if int(matches.split()[1]) > 10: 
                check_1_bool = False
                check_1_statements.append(matches) 
            # Contains Timeout 
    
    if timeout_found is False: 
        check_1_bool = False
        check_1_statements.append("No Timeout Definition Found.")
        
    if check_1_bool is False: 
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            results = "Ensure that the Timeout value is set to 10 or below\n\nTimeout 10"
            for i in check_1_statements:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose: 
           print(title + f' (passed)') 


# 9.2 
def ensure_the_keepalive_is_enabled(verbose=True): 
    title = "9.1 Ensure KeepAlive is Enabled"
    file_location = "/etc/apache2/apache2.conf"
    keepalive_found = False
    check_1_bool = False
    check_1_statements = []
    rule_1 = "Verify that the KeepAlive directive is on or not present (On by default)"
    regex_pattern_for_root = re.compile(".*KeepAlive\s.*")
    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    # If they have listen
    for matches in re.findall(regex_pattern_for_root, lines):
        para_check = matches[0:9]
        if "KeepAlive" == para_check:
            keepalive_found = True
            if str(matches.split()[1]) == "Off": 
                check_1_bool = False
                check_1_statements.append(matches) 
            elif str(matches.split()[1]) == "On":
                check_1_bool = True
            # Contains Timeout 
    
    if keepalive_found is False: 
        check_1_bool = True
        
    
    if check_1_bool is False: 
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            results = "Ensure that that KeepAlive value is set to On\nor removed from the Configuration"
            for i in check_1_statements:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose: 
           print(title + f' (passed)') 
 

# 9.3 
def ensure_max_keep_alive_requests_is_set_to_a_value_of_100_or_greater(verbose=True):
    title = "9.3 Ensure Max Keep Alive Request is set to > 100"
    file_location = "/etc/apache2/apache2.conf"
    keep_alive_request_found = False
    check_1_bool = False
    check_1_statements = []
    rule_1 = "Verify that the MaxKeepAliveRequests directive in the\nApache configuration to have a value of 100 or more.\n(If Directive is not present, it default is 100)"
    regex_pattern_for_root = re.compile(".*MaxKeepAliveRequests\s.*")
    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    # If they have listen
    for matches in re.findall(regex_pattern_for_root, lines):
        para_check = matches[0:20]
        
        if "MaxKeepAliveRequests" == para_check:
            keep_alive_request_found = True
            if int(matches.split()[1]) > 100: 
                check_1_bool = False
                check_1_statements.append(matches)
            
            else: 
                check_1_bool = True
            
    if keep_alive_request_found is False: 
        check_1_bool = True
        
    
    if check_1_bool is False: 
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            results = "Ensure that that KeepAlive value is set to "
            for i in check_1_statements:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose: 
           print(title + f' (passed)') 

# 9.4 
def ensure_the_keep_alive_timeout_is_below_15(verbose=True): 
    title = "9.4 Ensure KeepAliveTimeout is Set to a Value of 15 or Less"
    file_location = "/etc/apache2/apache2.conf"
    timeout_found = False
    check_1_bool = False
    check_1_statements = []
    rule_1 = "Verify that the KeepAliveTimeout directive in the\nApache configuration to have a value of 15 or less.\nIf the directive is not present the default value is 5 seconds."
    regex_pattern_for_root = re.compile(".*KeepAliveTimeout\s.*")
    config_file = open(file_location, 'r+')
    lines = config_file.read()
    config_file.close()
    
    # If they have listen
    for matches in re.findall(regex_pattern_for_root, lines):
        para_check = matches[0:16]
        if "KeepAliveTimeout" == para_check:
            timeout_found = True
            if int(matches.split()[1]) > 15: 
                check_1_bool = False
                check_1_statements.append(matches) 
            else: 
                check_1_bool = True
                
            # Contains Timeout 
    
    if timeout_found is False: 
        check_1_bool = True
        
    if check_1_bool is False: 
        if verbose:
            flagged_out_table = PrettyTable()
            flagged_out_table.title = title
            flagged_out_table.field_names = [ "Violated Rule", "Location" ,"Solution", "Configuration",]
            flagged_out_table.align = "l"
            flagged_out_table.valign = "t"
            results = "Ensure that the Timeout value is set to 15 or below\n\nTimeout 15"
            for i in check_1_statements:
                flagged_out_table.add_row([rule_1, file_location , results , i ])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                flagged_out_table.add_row(["","","",""])
                
            # for i in check_2_statements: 
            #     flagged_out_table.add_row([rule_2, file_location, rule_2_solution, i]) 

            print(flagged_out_table)
    else:
        if verbose: 
           print(title + f' (passed)') 

# 9.5 
def ensure_the_timeout_limits_is_set_to_40_or_less(verbose=True):
    pass

# Run all section 5 methods 
def section_5_methods(): 
    # 5.1
    ensure_access_to_os_root_directory()
    # 5.2
    ensure_options_for_web_root_directory_are_restricted()
    # 5.3 
    ensure_options_for_other_directories_are_minimized()
    # 5.5
    ensure_printenv_script_is_removed()
    # 5.6
    ensure_testcgi_script_is_removed
    # 5.7
    ensure_http_request_methods_are_restricted()
    # 5.8
    ensure_http_trace_method_is_disabled()
    # 5.10
    ensure_access_to_ht_files_is_restricted()
    # 5.11
    ensure_access_to_inappropriate_file_extensions_is_restricted()
    # 5.13
    ensure_ip_address_for_listening_for_requests_are_specified()
            
# Run all section 9 methods 
def section_9_methods(): 
    # 9.1
    ensure_the_timeout_is_set_to_10_or_less()
    # 9.2 
    ensure_the_keepalive_is_enabled()
    # 9.3
    ensure_max_keep_alive_requests_is_set_to_a_value_of_100_or_greater()
    # 9.4
    ensure_the_keep_alive_timeout_is_below_15()
    # 9.5 (Unsure)
    # 9.6 (Unsure)       
if __name__ == "__main__":
    
    section_5_methods()
    section_9_methods()
    # print(flagged_configurations[0])