### oscp_recon
OSCP recon tools

Original script from https://www.securitysift.com/offsec-pwb-oscp/
##Original Script Details##
[Title]: reconscan.py -- a recon/enumeration script
[Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift




##changelog##

#Refactored by J.Ruth
1.) Seperated port logic from nmapScan to recon_controller (seperate function for scale)
2.) Created create_folder function to create personalized folder structure
3.) Updated all output creations to match new folder structure
4.) Added dirb and nikto to http and https enumeration.
5.) Deprecated Brute forcing, might create a seperate function later in the control flow

##TODO##
- add in CURL and banner grab using NC
- add in argument control.
- add in more modular functionality for nse script selection (currently hardcoded).
- change UDP scan to Unicorn scan.
- update http nse scripts 
- update SNMP
- break down scripts onto single script - done
- Add in create_folder structure - done
- change folder paths and file names - done
- add in other web scans - done
- add in enum4linux - done
- seperate nmap Scan function so it's just responsible of pulling ports. - done
- create scan_controller function - done
- rename scan controller to recon_controller - done 
- seperate controller module to call functions.- done
- cleanup  all format strings consistent - done
