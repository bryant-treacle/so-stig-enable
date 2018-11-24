# Security Onion DoD Stig Compliance
This script will add additional the below controls to Security Onion 16.04.x in accordance with DoD RMF/STIG guidelines.  

## Login Banner:

    - Add SSH, Web, and Desktop Environment DoD consent banners prior to granting user access to the system.
    - Enforce DoD password policies to local user and Kibana/Sguil/Squert accounts.

## Password Compliance:
    - Enforces DoD Password Policies on any local server account created after the script.
    - Adds Compliance to the following STIG Finding IDs using the Application Security and Development Security Technical Implementation Guide.
        - V-69343 - The application must enforce the limit of three consecutive invalid logon attempts
        - V-69555 - The application must enforce a minimum 15-character password length.
        - V-69575 - The application must prohibit password reuse for a minimum of five generations.
        - V-69573 - The application must enforce a 60-day maximum password lifetime restriction.
        - V-69561 - The application must enforce password complexity by requiring that at least one numeric character be used.
        - V-69557 - The application must enforce password complexity by requiring that at least one upper-case character be used.
        - V-69559 - The application must enforce password complexity by requiring that at least one lower-case character be used.
        - V-69563 - The application must enforce password complexity by requiring that at least one special character be used.
        - V-69349 - The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.
        - V-69351 - The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.



## File list

    - dod_50-gnome.conf - session-setup-script added to generate desktop environment DoD consent popup.  To customize the test, add your text surrounded by quotes after --text switch.

    - dod_index.html/dod_banner.css - Landing page for https://localhost with DoD consent banner.  The I agree consent button will send user to the Main Security Onion index.php page.

    - dod_common-auth - Added line to enforce 60 min account lockout after 3 failed login attempts.  

    - dod_common-password - Added Line to enforce Min length, number of upper,lower,digits, and special characters.  Add number of rounds for encryption to 5000.

    - dod_login_banner - Text file that will be displayed on any SSH login.  Uses Message of The Day (MOTD) feature in linux, and the filename/location is defined in /etc/ssh/sshd_config.

    - dod_squil_password.sh  - Script to enforce DoD compliance for Squil/Kibana/Squert users.
