import os
import re
import subprocess
import distro
from getpass import getpass
import requests
import OpenSSL.crypto

def getPlatform():
    return distro.name()

def section71():
    #Check for 7.1 (TLDR: is mod_ssl installed?)
    ssl_module_enabled = subprocess.run("/usr/sbin/apache2ctl -M".split(), capture_output=True, text=True)
    if str(ssl_module_enabled).find("ssl_module") != -1:
        print("SSL Present and Loaded!")
    elif str(ssl_module_enabled).find("ssl_module") != -1:
        print("NSS Present and Loaded!")
    else:
        # Remediate for 7.1 (TLDR: Install and enable mod_ssl)
        input("Press any key to commence remediation for 7.1")
        #Installing mod_ssl (Check for Red Hat, since Ubuntu/Debian already have mod_ssl)
        if getPlatform().find("Red Hat") != -1:
            print("Installing mod_ssl...")
            subprocess.run("yum install mod_ssl".split(), capture_output=True, text=True)
        #Enable mod_ssl
        print("Enabling mod_ssl for apache2")
        output = subprocess.run("/usr/sbin/a2enmod ssl".split(), capture_output=True, text=True)
        output = subprocess.run("systemctl restart apache2".split(), capture_output=True, text=True)
def section72_check():
    print("The following certificates have issues and need to be reissued!")
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available | grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for sites in sites_available_list:
        file = open("/etc/apache2/sites-available/"+sites)
        file_lines = file.readlines()
        for file in range(len(file_lines)):
            if (file_lines[file].find("SSLCertificateFile") != -1) and (file_lines[file].find(".crt") != -1):
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    open(file_lines[file].split()[1]).read()
                )
                if (cert.has_expired() ):
                    expired_date = cert.get_notAfter().decode()
                    print(file_lines[file].split()[1] + " has expired since " + expired_date[0:4] + "-" + expired_date[4:6] +
                          "-" + expired_date[6:8] + ("(YYYY-MM-DD)"))
                elif (cert.get_signature_algorithm().decode().find("sha1") != -1) or\
                        (cert.get_signature_algorithm().decode().find("md5") != -1):
                    print(file_lines[file].split()[1] + " has a WEAK signature algorithm which is "
                          + cert.get_signature_algorithm().decode().split("with")[0])
                else:
                    print(file_lines[file].split()[1] + " is OK")

def section72_createcert():
    #Check for 7.2 (TLDR:THEREISNOTLDR THIS IS A PAIN IN THE ASS)
    website_name = input("Enter your common name (e.g. www.example.com): ")
    country = input("Enter your country (2 Letter Code): ")
    state = input("Enter your state: ")
    locality = input("Enter your locality(e.g. Glasgow): ")
    org = input("Enter your organisation's name: ")
    orgUnitName = input("Enter your organisation's unit name: ")
    password = getpass("Enter a passphrase for your private key: ")
    email = input("Enter an email address: ")
    #Generate Priv key
    subprocess.run("openssl genrsa -passout pass:" + password+ " -aes128 2048 > " + website_name + ".key",
                    shell=True)
    #Generate Template Config File
    csr_request = open("/etc/ssl/openssl.cnf", "r")
    csr_request_readlines = csr_request.readlines()
    for i in csr_request_readlines:
        if i.find("countryName_default") != -1:
            csr_request_readlines[csr_request_readlines.index(i)] = "countryName_default\t\t= " + country + "\n"
        elif i.find("stateOrProvinceName_default") != -1:
            csr_request_readlines[csr_request_readlines.index(i)] = "stateOrProvinceName_default\t\t= " + state + "\n"
        elif i.find("localityName			= Locality Name (eg, city)") != -1:
            csr_request_readlines.insert(csr_request_readlines.index(i) + 1, "localityName_default\t\t= " + locality + "\n" )
        elif i.find("0.organizationName_default") != -1:
            csr_request_readlines[csr_request_readlines.index(i)] = "0.organizationName_default\t\t= " + org + "\n"
        elif i.find("organizationalUnitName_default") != -1:
            csr_request_readlines[csr_request_readlines.index(i)] = "organizationalUnitName\t\t= " + orgUnitName + "\n"
        elif i.find("commonName			= Common Name (e.g. server FQDN or YOUR name)") != -1:
            csr_request_readlines.insert(csr_request_readlines.index(i) + 1, "commonName_default\t\t= " + website_name + "\n")
        elif i.find("emailAddress			= Email Address") != -1:
            csr_request_readlines.insert(csr_request_readlines.index(i) + 1, "emailAddresst\t= " + email + "\n")
    csr_write = open("configfile.cnf", "w")
    csr_write.write("".join(csr_request_readlines))
    csr_write.close()
    #Generate CSR from both
    print ("openssl req -new -config configfile.cnf -out " + website_name + ".csr -key " +
                   website_name + ".key")
    subprocess.run("openssl req -new -config configfile.cnf -out " + website_name + ".csr -key " +
                   website_name + ".key", shell=True)
    #Verify Info
    openssl_request = subprocess.run("openssl req -in " + website_name + ".csr --text | more", shell=True,
                                     capture_output=True, text=True)
    openssl_request_list = openssl_request.stdout.split("\n")
    for i in openssl_request_list:
        if i.find("Subject:") != -1:
            print(i)
    exit = input("Please verify the above information, type Y/N to continue/exit: ")
    if exit == "N" or exit =="n":
        quit()
    #Move private key to /etc/ssl/private
    subprocess.run("cp " + website_name + ".key /etc/ssl/private", shell=True, capture_output=True, text=True)
    print("Please send the generated CSR(.csr file) to a valid CA Authority to be signed.")
    print("Rerun this python script in 7.2 remediation mode when the CA returns a .crt file to you")

def section73():
    #Section7.3 Audit
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available | grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for j in sites_available_list:
        file = open("/etc/apache2/sites-available/"+j)
        file_lines = file.readlines()
        for i in file_lines:
            if i.find("\t\tSSLCertificateFile") != -1:
                i = i.strip("\t\tSSLCertificateFile")
                i = i.strip("\n")
                try:
                    cert_read = open(i, "r")
                    overwrite = 0
                    counter = 0
                    temp_string = ""
                    original_cert = ""
                    for cert in cert_read.readlines():
                        if cert.find("BEGIN PRIVATE KEY") != -1:
                            overwrite = 1
                        if overwrite == 1:
                            temp_string += cert
                        elif overwrite == 0:
                            original_cert += cert
                        if cert.find("END PRIVATE KEY") != -1:
                            overwrite = 0
                        counter += 1
                    # Replace original cert with safe non pw cert
                    cert_read = open(i, "w")
                    cert_read.write(original_cert)
                    # Make new cert at a safe location
                    print(i.split("/")[-1].split(".")[0])
                    priv_key = open("/etc/ssl/private/" + i.split("/")[-1].split(".")[0] + ".key", "w+")
                    priv_key.write(temp_string)
                except FileNotFoundError:
                    print(i + " not found")
            elif i.find("\t\tSSLCertificateKeyFile") != -1:
                i = i.strip("\t\tSSLCertificateKeyFile")
                i = i.strip("\n")
                perms = subprocess.run("stat -c \"%a %n \" "+i, shell=True, capture_output=True, text=True).stdout
                owner = subprocess.run("stat -c \"%U %G\" " + i, shell=True, capture_output=True, text=True).stdout
                perms_octal = perms.split(" ")[0]
                user_owner = owner.split(" ")[0]
                group_owner = owner.split(" ")[1]
                group_owner = group_owner.strip("\n")
                if (user_owner != "root" or group_owner != "root"):
                    subprocess.run("chown root:root "+i, shell=True, capture_output=True, text=True)
                    print("Owners fixed to root:root for " + i)
                if perms_octal != "400":
                    subprocess.run("chmod 400 "+i, shell=True, capture_output=True, text=True)
                    print("Permissions set to 400 for " + i)

def remediate72():
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available | grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    counter = 1
    for i in sites_available_list:
        print(str(counter) + ")" + i)
        counter += 1
    website = input("Enter your website's config file name (number): ")
    website = sites_available_list[int(website) - 1]
    #Move crt to /etc/ssl/certs, mod 0444
    filename = input("Enter your .crt name: ")
    subprocess.run("cp "+filename + " /etc/ssl/certs", shell=True, capture_output=True, text=True)
    subprocess.run("chmod 0444 " + filename, shell=True, capture_output=True, text=True)
    #Get key name
    keys_available = subprocess.run("ls -p /etc/ssl/private | grep -v /", shell=True, capture_output=True, text=True)
    keys_available_list = keys_available.stdout.split("\n")
    keys_available_list.pop()
    counter = 1
    for i in keys_available_list:
        print(str(counter) + ")" + i)
        counter += 1
    key = input("Enter your key file name (number): ")
    key = keys_available_list[int(key) - 1]
    #Read website name with common name and modify SSLCertificateFile and SSLCertificateKeyFile
    website_file = open("/etc/apache2/sites-available/"+website, "r")
    website_file_readlines = website_file.readlines()

    #Check for existing SSL Directives
    sslcert_found = 0
    sslcertkey_found = 0
    sslengine_enabled = 0
    for i in website_file_readlines:
        if i.find("\t\tSSLCertificateFile") != -1:
            website_file_readlines[website_file_readlines.index(i)] = "\t\tSSLCertificateFile\t/etc/ssl/certs/" \
                                                                             +filename + "\n"
            sslcert_found = 1
        elif i.find("\t\tSSLCertificateKeyFile") != -1:
            website_file_readlines[website_file_readlines.index(i)] =  "\t\tSSLCertificateKeyFile\t/etc/ssl/private/" \
                                                                       + key + "\n"
            sslcertkey_found = 1
        elif i.find("SSLEngine") != - 1:
            website_file_readlines[website_file_readlines.index(i)] = "\t\tSSLEngine on\n"
            sslengine_enabled = 1

    if sslcert_found == 0 or sslcertkey_found == 0 or sslengine_enabled == 0:
        for i in website_file_readlines:
            if (i.find("VirtualHost") != -1) and (i.find("443") != -1):
                if (sslcert_found == 0):
                    website_file_readlines.insert(website_file_readlines.index(i) + 1, "\t\tSSLCertificateFile\t/etc/ssl/certs/"
                                          +filename + "\n")
                if (sslcertkey_found == 0):
                    website_file_readlines.insert(website_file_readlines.index(i) + 1,
                                                  "\t\tSSLCertificateKeyFile\t/etc/ssl/private/"
                                                  + key + "\n")
                if (sslengine_enabled == 0):
                    website_file_readlines.insert(website_file_readlines.index(i) + 1,
                                                  "\t\tSSLEngine on\n")
    #Write to file
    subprocess.run("cp /etc/apache2/sites-available/" + website + " /etc/apache2/sites-available/"
                   + website + ".backup", shell=True)#, text=True, capture_output=True)
    with open("/etc/apache2/sites-available/" + website, "w") as f:
        f.write("".join(website_file_readlines))
    f.close()
    website_file.close()
    #Restart HTTPD
    print("Restarting apache2 service...")
    output = subprocess.run("systemctl restart apache2".split(), capture_output=True, text=True)

def section74():
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available| grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for sites in sites_available_list:
        site_open = open("/etc/apache2/sites-available/" + sites, "r")
        site_open_lines = site_open.readlines()
        sslprotocol_checked = 0
        for lines in range(len(sites)):
            if site_open_lines[lines].find("SSLProtocol") != -1:
                site_open_lines[lines] = "\t\tSSLProtocol TLSv1.2"
                sslprotocol_checked = 1
                break
        if sslprotocol_checked == 0:
            for lines in range(len(sites)):
                if site_open_lines[lines].find(":443") != -1:
                    site_open_lines.insert(lines + 2, "\t\tSSLProtocol TLSv1.2 TLSV1.3\n")
        write_file = open("/etc/apache2/sites-available/" + sites, "w")
        write_file.write("".join(site_open_lines))

def section75():
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available | grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for sites in sites_available_list:
        site_open = open("/etc/apache2/sites-available/" + sites, "r")
        site_open_lines = site_open.readlines()
        honorcipher = 0
        ciphersuite = 0
        for lines in range(len(sites)):
            if site_open_lines[lines].find("SSLHonorCipherOrder") != -1:
                site_open_lines[lines] = "\t\tSSLHonorCipherOrder On\n"
                honorcipher = 1
            elif site_open_lines[lines].find("SSLCipherSuite") != -1:
                site_open_lines[lines] = "\t\tSSLCipherSuite EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA\n"
                ciphersuite = 1
        if honorcipher == 0:
            for lines in range(len(sites)):
                if site_open_lines[lines].find(":443") != -1:
                    site_open_lines.insert(lines + 2, "\t\tSSLHonorCipherOrder On\n")
        if ciphersuite == 0:
            for lines in range(len(sites)):
                if site_open_lines[lines].find(":443") != -1:
                    site_open_lines.insert(lines + 2,
                                           "\t\tSSLCipherSuite EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA\n")
        write_file = open("/etc/apache2/sites-available/" + sites, "w")
        write_file.write("".join(site_open_lines))

def section76():
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available| grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for sites in sites_available_list:
        site_open = open("/etc/apache2/sites-available/" + sites, "r")
        site_open_lines = site_open.readlines()
        insecure_checked = 0
        for lines in range(len(sites)):
            if site_open_lines[lines].find("SSLInsecureRenegotiation") != -1:
                site_open_lines[lines] = "\t\tSSLInsecureRenegotiation off\n"
                insecure_checked = 1
                break
        if insecure_checked == 0:
            for lines in range(len(sites)):
                if site_open_lines[lines].find(":443") != -1:
                    site_open_lines.insert(lines + 2, "\t\tSSLInsecureRenegotiation off\n")
        write_file = open("/etc/apache2/sites-available/" + sites, "w")
        write_file.write("".join(site_open_lines))

def section77():
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available| grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for sites in sites_available_list:
        site_open = open("/etc/apache2/sites-available/" + sites, "r")
        site_open_lines = site_open.readlines()
        for lines in range(len(sites)):
            if site_open_lines[lines].find("SSLCompression") != -1:
                site_open_lines[lines] = "\t\tSSLCompression off\n"
                break
        write_file = open("/etc/apache2/sites-available/" + sites, "w")
        write_file.write("".join(site_open_lines))

def section79():
    all_configs = subprocess.run("find /etc/apache2/ -name '*.conf'", shell=True, capture_output=True, text=True)
    all_configs = all_configs.stdout.split("\n")
    all_configs.pop()

    ip_address_list = []
    vhost_list = []
    final_list = []
    origin = []
    redirect_code = ["300", "301", "302", "303", "304", "307", "308", "400"]

    for configs in all_configs:
        site_open = open(configs, "r")
        site_open_lines = site_open.readlines()
        for lines in range(len(site_open_lines)):
            if site_open_lines[lines].find("<VirtualHost") != -1 and site_open_lines[lines].find("#") == -1:
                vhost_list.append(site_open_lines[lines].strip("\n").strip("\t"))
                origin.append((site_open_lines[lines].strip("\n").strip("\t"), configs))
            elif site_open_lines[lines].find("Listen") != -1:
                ip_address_list.append(site_open_lines[lines].strip("\n").strip("\t"))
                origin.append((site_open_lines[lines].strip("\n").strip("\t"), configs))

    #Get all listening IP Addresses
    #print (ip_address_list)
    #Get all VHOST URLs
    #print (vhost_list)
    #cleanup lists
    for ip_address in ip_address_list:
        ip_address = ip_address.split(" ")
        if(ip_address[1].find(".") == -1):
            continue
        elif ip_address[2] != "443":
            final_list.append(ip_address[1] + ":" + ip_address[2])
    for vhost in vhost_list:
        vhost = vhost.strip("<").strip(">")
        vhost = vhost.split(" ")
        if vhost[1].find(":443") != -1:
            continue
        else:
            final_list.append(vhost[1])
    print(final_list)
    #attempt request with http://<vhost/IP>/
    print("The following URLs/IPs are still serving non HTTP content! This makes the web server non compliant with"
          " CIS 7.9")
    print("For each of these URLs, they must redirect to a https website using the following directive: ")
    print("e.g.(Redirect permanent / https://www.example.com/)")
    print("===================================================")
    for candidate in final_list:
        try:
            request = requests.get("http://" + candidate.replace("*", "127.0.0.1") +"/")
            status_code = str(request.status_code)
            index = redirect_code.index(status_code)
        except ValueError:
            print("URL " + "http://" + candidate + "/" + " serving HTTP content! Return code is " + status_code)
            for configs in all_configs:
                site_open = open(configs, "r")
                site_open_lines = site_open.readlines()
                for lines in range(len(site_open_lines)):
                    if site_open_lines[lines].find(candidate) != -1:
                        print("Directive can be found here: " + configs)
            continue
        except:
            print("Connection error with host " + candidate)
    #See if request gives 400 bad request or not
    #400 bad request/redirect = GOOD
    #anything else = BAD tell the user to go fuck himself and enable tls on the vhost


def section711():
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available| grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for sites in sites_available_list:
        site_open = open("/etc/apache2/sites-available/" + sites, "r")
        site_open_lines = site_open.readlines()
        stapling_check = 0
        staplingcache_check = 0
        for lines in range(len(sites)):
            if site_open_lines[lines].find("SSLUseStapling") != -1:
                site_open_lines[lines] = "\t\tSSLUseStapling On\n"
                stapling_check = 1
            elif site_open_lines[lines].find("SSLStaplingCache") != -1:
                site_open_lines[lines] = "\t\tSSSLStaplingCache \"shmcb:logs/ssl_staple_cache(512000)\"\n"
                staplingcache_check = 1
        if stapling_check == 0:
            for lines in range(len(sites)):
                if site_open_lines[lines].find(":443") != -1:
                    site_open_lines.insert(lines + 2, "\t\tSSLUseStapling On\n")
        if staplingcache_check == 0:
            for lines in range(len(sites)):
                if site_open_lines[lines].find(":443") != -1:
                    site_open_lines.insert(lines + 2, "\t\tSSLStaplingCache \"shmcb:logs/ssl_staple_cache(512000)\"\n")
        write_file = open("/etc/apache2/sites-available/" + sites, "w")
        write_file.write("".join(site_open_lines))

def section712():
    sites_available = subprocess.run("ls -p /etc/apache2/sites-available| grep -v /", shell=True, capture_output=True, text=True)
    sites_available_list = sites_available.stdout.split("\n")
    sites_available_list.pop()
    for sites in sites_available_list:
        site_open = open("/etc/apache2/sites-available/" + sites, "r")
        site_open_lines = site_open.readlines()
        strict_transport = 0
        for lines in range(len(sites)):
            if site_open_lines[lines].find("Header always set Strict-Transport-Security") != -1:
                site_open_lines[lines] = "\t\tHeader always set Strict-Transport-Security \"max-age=600\"\n"
                strict_transport = 1
        if strict_transport == 0:
            for lines in range(len(sites)):
                if site_open_lines[lines].find(":443") != -1:
                    site_open_lines.insert(lines + 2, "\t\tHeader always set Strict-Transport-Security \"max-age=600\"\n")
        print("".join(site_open_lines))
        print("==============")

def section81():
    site_open = open("/etc/apache2/apache2.conf", "r")
    site_open_lines = site_open.readlines()
    strict_transport = 0
    for lines in range(len(site_open_lines)):
        if site_open_lines[lines].find("ServerTokens") != -1:
            site_open_lines[lines] = "ServerTokens Prod\n"
            strict_transport = 1
    if strict_transport == 0:
        site_open_lines.append("ServerTokens Prod\n")
    print("".join(site_open_lines))
    print("==============")

def section82():
    site_open = open("/etc/apache2/apache2.conf", "r")
    site_open_lines = site_open.readlines()
    strict_transport = 0
    for lines in range(len(site_open_lines)):
        if site_open_lines[lines].find("ServerSignature") != -1:
            site_open_lines[lines] = "ServerSignature Off\n"
            strict_transport = 1
    if strict_transport == 0:
        site_open_lines.append("ServerSignature Off\n")
    print("".join(site_open_lines))
    print("==============")

def section83():
    all_configs = subprocess.run("find /etc/apache2/ -name '*.conf'", shell=True, capture_output=True, text=True)
    all_configs = all_configs.stdout.split("\n")
    all_configs.pop()
    for configs in all_configs:
        file = open(configs,"r")
        file = file.readlines()
        for lines in range(len(file)):
            if file[lines].find("Alias /icons/") != -1:
                file[lines] = "\t#" + file[lines].strip("\t")
        print("".join(file))
        print("==============")

def section84():
    all_configs = subprocess.run("find /etc/apache2/ -name '*.conf'", shell=True, capture_output=True, text=True)
    all_configs = all_configs.stdout.split("\n")
    all_configs.pop()
    for configs in all_configs:
        file = open(configs,"r")
        file = file.readlines()
        for lines in range(len(file)):
            if lines > len(file) - 1:
                break
            if file[lines].find("FileETag") != -1:
                del file[lines]
        print("".join(file))
        print("==============")
section72_check()
#remediate72()
#section73()
#section74()
#section75()
#section76()
#section77()
#SECTION78 IS ALREADY DONE IN 76
#section79()
#SECTION710 IS ALREADY DONE IN 74
#section711() #Enable OCSP Stapling
#section712() #HTTP Strict Transport
#SECTION713 IS ALREADY DONE IN 76
#section81() #Check for ServerTokens set to "Prod"
#section82() #Check for ServerSignature Off
#section83() #Comment out Alias icons/ "/var/www/icons/"
#section84() #Remove all instances of FileETag
