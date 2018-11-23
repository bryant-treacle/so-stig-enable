# security_onion_dod_compliance
This script will add additional the below controls to Security Onion 16.04.x in accordiance with DoD RMF/STIG guidelines.  

## Login Banner:

    - Add SSH, Web, and Desktop Enviroment DoD consent banners prior to granting user access to the system.
    - Enforce DoD password policies to local user and Kibana/Sguil/Squert accounts.

## Password Complience:
    - Enforces DoD Password Policies on any local server account created after the script 
    
    - Adds Complince to the following STIG Rule IDs
        - SV-84177r1_rule -minimum 15-character password length
        - SV-84179r1_rule 
## File list

dod_50-gnome.conf - session-setup-script added to generate desktop enviroment DoD consent popup.  To customize the test, add your text surrounded by quotes after --text switch.

dod_index.html/dod_banner.css - Landing page for https://localhost with DoD consent banner.  I agree consent button will send user to the Main Security Onion index.php page.

dod_common-auth - Added line to enforce 60 min account lockout afte r 3 failed login attempts.  

dod_common-password - Added Line to enforce Min lenght, number of upper,lower,digits, and special characters.

dod_login_banner - Text file that will be displayed on any SSH login.  Uses Message of The Day (MOTD) feature in linux, and the filename/location is defined in /etc/ssh/sshd_config.

dod_squil_password.sh  - Script to enfore DoD complience for Squil/Kibana/Squert users.
