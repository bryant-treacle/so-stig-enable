# Security Onion DoD Stig Compliance
This script will add additional the below controls to Security Onion 16.04.x in accordance with DoD RMF/STIG guidelines.  

## Usage:
    This script contains all necessary additional deb packages required for STIG compliance.  
    1. Download or Clone the Repo
    2. If download unzip using *so-stig-enable.zip*
    3. cd so-stig-enable
    4. sudo chmod 755 so-stig-enable
    5. sudo ./so-stig-enable
    
    This script will apply Canical Ubuntu 16.04 LTS STIG’s to Security Onion 16.04.5.6 when configured as a Master, Heavy Node, Forward Node, or Storage Node.  If you are running a different release, please choose the branch for that release.  
    
    The deb_packages folder contains all necessary packages and dependencies for use on Air Gapped networks.  If internet access is available, please run SOUP at your earliest convenience to ensure those packages are up-to-date.
    
    This script has been designed to be ran as many times if needed to verify updates or changes to configuration files have not overwritten any STIG requirements.
    
    Below are a summary of the STIG findings after the script has been executed.

    Overall Totals
    Total: 230
    Not a Finding: 184
    Open: 35
    Not Applicable: 11

    CAT I
    Total: 22
    Not a Finding: 17
    Open: 5

    CAT II
    Total: 200
    Not a Finding: 164
    Open: 27
    Not Applicable: 9

    CAT III
    Total: 8
    Not a Finding: 3
    Open: 3
    Not Applicable: 2

    Open: These checks are either dependent on the policies or hardware configurations of the organization and must be addressed locally.

    A copy of the unclassified STIG Viewer and completed checklist has been included in the Repo.  The STIG View does require a java runtime environment in order to launch.  

    
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
