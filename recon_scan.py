#!/usr/bin/env

##Original Script Details##
###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
##-------------------------------------------------------------------------------------------------------------

##changelog
###############################################################################################################
## Refactored by J.Ruth
## 1.) Seperated port logic from nmapScan to recon_controller (seperate function for scale)
## 2.) Created create_folder function to create personalized folder structure
## 3.) Updated all output creations to match new folder structure
## 4.) Added dirb and nikto to http and https enumeration.
## 5.) Deprecated Brute forcing, might create a seperate function later in the control flow
##-------------------------------------------------------------------------------------------------------------


# TODO
#add in CURL and banner grab using NC
#add in argument control.
#add in more modular functionality for nse script selection (currently hardcoded).
# change UDP scan to Unicorn scan.
# update http nse scripts 
# update SNMP

# break down scripts onto single script - done
# Add in create_folder structure - done
# change folder paths and file names - done
# add in other web scans - done
# add in enum4linux - done
#seperate nmap Scan function so it's just responsible of pulling ports. - done
#create scan_controller function - done
#rename scan controller to recon_controller - done 
#seperate controller module to call functions.- done
#cleanup  all format strings consistent - done


import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time


def multProc(targetin, scanip, port): #multi-processing function from original script
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return


def create_folders(ip_address):  #folder creation script 
    #host/enumeration, host/exploitation, host/post_exploitation, host/post_exploitation

    dir_list = ["/enumeration", "/exploitation/exploits",
        "/exploitation/priv_escalation", "/post_exploitation"]

    for dir in dir_list:
        path = ip_address + dir
  
        cmd = "mkdir -m 755 -p {0}".format(path)  # -p create all required parents ignore dups
        p = subprocess.call(cmd.split())


    print "INFO: Folder Structure Created for {0}".format(ip_address)
    return


def dnsEnum(ip_address, port): #dnsEnumeration script
    print "INFO: Detected DNS on {0}:{1}".format(ip_address, port)
    if port.strip() == "53":
        HOSTNAME = "nmblookup -A {0} | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1".format(
            ip_address)
        # strip hostname from results.
        host = subprocess.check_output(HOSTNAME, shell=True).strip()

        print "INFO: Attempting Domain Transfer on {0} ".format(host)
        ZT = "dig @{0}.thinc.local thinc.local axfr".format(host)
        # try a zone transfer on the host.
        ztresults = subprocess.check_output(ZT, shell=True)
        if "failed" in ztresults:
            print "INFO: Zone Transfer failed for {0}".format(host)
        else:
            print "[*] Zone Transfer successful for {0} ({1})!!! [see output file]".format(host,ip_address)
            # output zone transfer success to results file.
            outfile = "{0}/enumeration/{0}_zonetransfer.txt".format(ip_address)
            dnsf.close
    return

def httpEnum(ip_address, port):
    print "INFO: Detected http on {0}:{1}".format(ip_address,port)
    print "INFO: Performing nmap web script and dirb with common wordlist and NIKTO scan for {0}:{1} ".format(ip_address,port)
    HTTPSCAN = "nmap -sV -Pn -vv -p {0} --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN {1}/enumeration/{1}_{0}_http_nse.txt {1}".format(port, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    #dirb with default wordlist (common)
    DIRBUST = "dirb http://{0}:{1} -r -o {0}/enumeration/{0}_{1}_dirb_http.txt".format(ip_address, port) #don't enter any folders
    #nikto scan
    NIKTOSCAN = "nikto -h http://{0}:{1} -o \'{0}/enumeration/{0}_{1}_nikto_http.txt\'".format(ip_address, port)
    print NIKTOSCAN
    subprocess.call(NIKTOSCAN, shell=True)
    subprocess.call(DIRBUST, shell=True)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on {0}:{1}".format(ip_address,port)
    print "INFO: Performing nmap web script and dirb with common wordlist and NIKTO scan for {0}:{1} ".format(ip_address,port)
    HTTPSCAN = "nmap -sV -Pn -vv -p {0} --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN {1}/enumeration/{1}_{0}_http_nse.txt {1}".format(port, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    #dirb with default wordlist (common)
    DIRBUST = "dirb https://{0}:{1} -r -o {0}/enumeration/{0}_{1}_dirb_https.txt".format(ip_address, port) #don't enter any folders
    #nikto scan 
    NIKTOSCAN = "nikto -h https://{0}/:{1} -o \'{0}/enumeration/{0}_{1}_nikto_https.txt\'".format(ip_address, port)
    print NIKTOSCAN
    subprocess.call(NIKTOSCAN, shell=True)
    subprocess.call(DIRBUST, shell=True)
    return

def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on {0}:{1}".format(ip_address,port)
    print "INFO: Performing nmap mssql script scan for {0}:{1}".format(ip_address,port)
    #MSSQL nse scripts
    MSSQLSCAN = "nmap -vv -sV -Pn -p {0} --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN {1}/enumeration/{1}_mssql_nse.txt {1}".format(port, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)

def sshEnum(ip_address, port):
    print "INFO: Detected SSH on {0}:{1} Skipping...".format(ip_address,port)
    return

def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on {0}:{1} Skipping...".format(ip_address,port)
    # SCRIPT = "./snmprecon.py %s" % (ip_address)
    # subprocess.call(SCRIPT, shell=True)
    return

def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on {0}:{1} Skipping...".format(ip_address,port)
    print "/nSkipping any action, investigate manually"
    # if port.strip() == "25":
    #   SCRIPT = "./smtprecon.py %s" % (ip_address)
    #   subprocess.call(SCRIPT, shell=True)
    # else:
    #   print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)"
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on {0}:{1}".format(ip_address,port)
    #if port.strip() == "445":
        #SCRIPT = "./smbrecon.py {0} 2>/dev/null".format(ip_address)
    ENUM4LINUX = "enum4linux -a -v {0}".format(ip_address)
    results = subprocess.check_output(ENUM4LINUX, shell=True)
    outfile = "{0}/enumeration/{0}_enum4linux.txt".format(ip_address)
    f = open(outfile, "w")
    f.write(results)
    f.close
    return

def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on {0}:{1}".format(ip_address,port)
    FTPSCAN = "nmap -sV -Pn -vv -p {0} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN {1}/enumeration/{1}_ftp_nse.txt {1}".format(port, ip_address)
    results = subprocess.check_output(FTPSCAN, shell=True)
    #outfile = "{0}/enumeration/{0}_ftprecon.txt".format(ip_address)
    #f = open(outfile, "w")
    #f.write(results)
    #f.close
    return


def recon_controller(ip_address, services): #function to take in ports from namp scans and trigger other scans
    #print "Now printing serv_dict from scan_controller"
    #print services
    for service in services:
      print "Now checking port: {0}".format(services[service])
      ports = services[service]
      if ("http" == service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(httpEnum, ip_address, port)
      elif (service == "ssl/http") or ("https" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(httpsEnum, ip_address, port)
      elif ("netbios-ssn" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(smbEnum, ip_address, port)
      elif ("ssh" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              # multProc(sshEnum, ip_address, port)
      elif ("smtp" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(smtpEnum, ip_address, port)  
      elif ("snmp" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(snmpEnum, ip_address, port)    
      elif ("domain" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(dnsEnum, ip_address, port)                   
      elif ("ftp" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(ftpEnum, ip_address, port)                    
      elif ("microsoft-ds" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(smbEnum, ip_address, port)
      elif ("ms-sql" in service):
          for port in ports:
              port = port.split("/")[0]
              print "{0} found: {1}".format(service,port)
              multProc(mssqlEnum, ip_address, port)
    return 
    
def nmapScan(ip_address):  
    """Unit testing code block for testing without having to run NMAP scan over and over
    #lines = ""
    #lines += "PORT   STATE SERVICE REASON         VERSION\n"
    #lines += "22/tcp open  ssh     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n"
    #lines += "445/tcp open  https     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "53/tcp open  domain     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "3306/tcp open  ms-sql     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "23/tcp open  smtp     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "24/tcp open  snmp     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "25/tcp open  ftp     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "139/tcp open  microsoft-ds     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "22/tcp open  ssh     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    #lines += "22/tcp open  ssh     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)\n"
    """
    serv_dict = {}
    ip_address = ip_address.strip()
    print "INFO: Running general TCP/UDP nmap scans for {0}".format(ip_address)
    serv_dict = {}
    TCPSCAN = "nmap -vv -Pn -sC -sV -T 4 -p- -oX {0}/enumeration/{0}_TCP.xml -oN {0}/enumeration/{0}_TCP.txt {0}".format(ip_address)
    #UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oX {0}/enumeration/{0}_UDP.xml -oN {0}/enumeration/{0}_UDP.txt {0}".format(ip_address)
    results = subprocess.check_output(TCPSCAN, shell=True)
    #udpresults = subprocess.check_output(UDPSCAN, shell=True)
    lines = results.split("\n")
    # print "line 6: {0}".format(lines)
  

    for line in lines:
        # print "line 7: {0}".format(line)
        ports = []    
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            # print "line  12: {0}".format(line)
            while "  " in line:
                line = line.replace("  ", " ")
            linesplit= line.split(" ")
            # print "\nline 15: {0}".format(linesplit)
            port = line.split(" ")[0] # grab the port/proto
            service = linesplit[2] # grab the service name
            # print "line 18: service = {0}\n".format(service)
            # print "line 17: port = {0}\n".format(port)
            # print "checking if service in serv_dict"
            if service in serv_dict:
                ports = serv_dict[service] # if the service is already in the dict, grab the port list
                # print "port already found"
            ports.append(port)
            # print "line 24: ports = {0}\n".format(ports)
            serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
    
    print "INFO: TCP/UDP Nmap scans completed for {0} now sending the port list to the recon controller ".format(ip_address)
    recon_controller(ip_address, serv_dict)

    return

# grab the discover scan results and start scanning up hosts
print "############################################################"
print "####                      RECON SCAN                    ####"
print "####            A multi-process service scanner         ####"
print "####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####"
print "############################################################"

if __name__=='__main__':
    f = open('targets.txt', 'r') #targets.txt should be in the folder you are running script from and where you want to create tree.
    for scanip in f:
       ip = scanip.replace("\n", "")
       create_folders(ip)
       jobs = []
       p = multiprocessing.Process(target=nmapScan, args=(ip,))
       jobs.append(p)
       p.start()
    f.close()
