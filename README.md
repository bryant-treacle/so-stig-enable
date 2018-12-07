# Security Onion DoD Stig Compliance
This script will add additional the below controls to Security Onion 16.04.x in accordance with DoD RMF/STIG guidelines.  

## Usage:
    This script contains all necessary additional deb packages required for STIG compliance.  
    1. Download or Clone the Repo
    2. If download unzip using *unzip security_onion_dod_compliance-master.zip*
    3. cd security_onion_dod_compliance-master/
    4. sudo chmod 755 dod_compliance.sh
    5. sudo ./dod_compliance.sh
    
## Login Banner:
    - Add SSH, Web, and Desktop Environment DoD consent banners prior to granting user access to the system.
    - Enforce DoD password policies to local user and Kibana/Sguil/Squert accounts.

## Password Compliance:
    - Enforces DoD Password Policies on any local server account created after the script.
    - Adds Compliance to the following STIG Finding IDs using the Application Security and Development Security Technical Implementation Guide.
    
## Bruteforce account lockout:
    - Enforces DoD brute force account lockout requirements.
    - For local server accounts you will need to change to run sudo passwd <locked user> commamnd to re-enable the account.
    - For Kibana/Sguil/Squert accounts you will need to run the so-user-passwd command to re-enable the account.
       
## File list:

    - dod_50-gnome.conf - session-setup-script added to generate desktop environment DoD consent popup.  To customize the test, add your text surrounded by quotes after --text switch.

    - dod_index.html/dod_banner.css - Landing page for https://localhost with DoD consent banner.  The I agree consent button will send user to the Main Security Onion index.php page.

    - dod_common-auth - Added line to enforce 60 min account lockout after 3 failed login attempts.  

    - dod_common-password - Added Line to enforce Min length, number of upper,lower,digits, and special characters.  Add number of rounds for encryption to 5000.

    - dod_login_banner - Text file that will be displayed on any SSH login.  Uses Message of The Day (MOTD) feature in linux, and the filename/location is defined in /etc/ssh/sshd_config.

    - dod_squil_password.sh  - Script to enforce DoD compliance for Squil/Kibana/Squert users.
