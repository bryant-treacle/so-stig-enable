#! /bin/bash -i
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Bryant Treacle
#
# Date Created: 27 Nov 18
#
# Last Modified: 7 Ded 18



####################
#  Welcome Script  #
####################
welcome_script()
{
cat << EOF 

This script will make the following changes to Security Onion 16.04 in order to meet DoD STIG Requirements for Canonical Ubuntu 16.04 EXCEPT:
    - CAT I STIG Vul ID: V-75503 - The requirement to use FIPS 140-2 Certified Modules.  This requires a subscription to Ubuntu Advantage Advanced
    - CAT I STIG Vul ID: V-78005 - The system must use a DoD-approved virus scan program (unique to each installation).   
    - CAT I STIG Vul ID: V-75505,75507 - Systems booted with a BIOS must require authentication (unique to each installation)
    - CAT II STIGs dealing with file permissions for individual users (unique to each installation).
    - CAT II STIGs dealing with Common Access Card login requirments.  The required packages are installed.

EOF
echo "Would you like to enforece DoD Stigs on this server? (Y/n)"
read user_continue_prompt

if [ ${user_continue_prompt,,} != "y" ] ; then
    echo "Exiting script!"
    exit
fi
}

###################################
#         DoD login Banners       #
#  STIG Vul ID's: V-75393, 75435  #
###################################
login_banner()
{
# Add banner file location to sshd_config
# Vul ID: V-75825 | Severity: CAT II
sed -i 's|#Banner /etc/issue.net|Banner /etc/dod_login_banner|g' /etc/ssh/sshd_config
sudo cp files/dod_login_banner /etc/dod_login_banner
systemctl restart sshd

# This will add a DoD consent splash page for web access
# This only works because Apache2 will load index.html before index.php.  This can be modified in the
# /etc/apache2/mods-enabled/dir.conf
cp files/dod_index.html /var/www/so/index.html
cp files/dod_banner.css /var/www/so/css

# DoD consent Splash Page for gnome login.
cp files/dod_50-gnome.conf /usr/share/lightdm/lightdm.conf.d/50-gnome.conf
}

########################################
#           Local Login Controls       #
#  STIG Vul ID: V-75479, 75487, 75493  #
########################################
common_auth()
{
sudo cp files/dod_common-auth /etc/pam.d/common-auth
}
#####################
#  Max Login limit  #
#  Vul ID: V-75443  #
#####################
max_login_limit()
{
echo '* hard maxlogins 10' >> /etc/security/limits.conf
}

#######################
#     Remove telnet   #
#  STIG Vul ID 75797  #
#######################
telnet_remove()
{
sudo apt-get -y remove telnet
}
####################################
#           login defs             #
#  STIG Vul ID's: V-75471, 75473,  # 
#  75561, 75543                    #
####################################
login.defs()
{
sed -i 's|PASS_MIN_DAYS.*|PASS_MIN_DAYS   1|g' /etc/login.defs
sed -i 's|PASS_MAX_DAYS.*|PASS_MAX_DAYS   60|g' /etc/login.defs
echo "CREATE_HOME yes" >> /etc/login.defs
sed -i 's|UMASK.*|UMASK 077|g' /etc/login.defs
}
################################
#  Account Inactivity disable
#  STIG Vul ID: V-75485
################################
inactive_accounts()
{
useradd -D -f 35
}

###############################
#  Account inactivity logout
# STIG Vul ID: V-75441
###############################
inactivity_logout()
{
sudo printf '#!/bin/bash\nTMOUT=900\nreadonly TMOUT\nexport TMOUT' > /etc/profile.d/autologout.sh
sudo chmod 755 /etc/profile.d/autologout.sh
}
#################################################
#  Set Password Complexity                      #
#  STIG Vul ID's: V-75449, 75451, 75453,75455,  #
#  75457, 75475, 75477                          #
#################################################
password_complexity()
{
sudo cp files/dod_common-password /etc/pam.d/common-password
sudo dpkg -i deb_packages/libpam-cracklib_1.1.8-3.2ubuntu2_amd64.deb
sudo cp files/dod_sguil_password.sh /usr/sbin/so-user-add-dod
sudo chmod 755 /usr/sbin/so-user-add-dod
sudo cp files/so-user-passwd-dod /usr/sbin/so-user-passwd-dod
sudo chmod 755 /usr/sbin/so-user-passwd-dod
# Adding dictionary password check requirement
echo "dictcheck=1" >> /etc/security/pwquality.conf
}

#####################################
#    PermitUserEnv. in sshd.conf    #
# Vul ID: V-75833,V-75829,V-75831,  #
# V-75841, 75827, 75851             #
#####################################
sshd_conf()
{
printf '# DoD Stig Vul ID: V-75833\nPermitUserEnvironment no\n\n#DoD STIG Vul ID: V-75829\nCiphers aes128-ctr,aes192-ctr,aes256-ctr\n\n#DoD STIG Vul ID: V-75831\nMACs hmac-sha2-256,hmac-sha2-512\n\n#DoD STIG Vul ID: V-75851\nCompression no' >> /etc/ssh/sshd_config
sed -i 's|#IgnoreUserKnownHosts yes|IgnoreUserKnownHosts yes|g' /etc/ssh/sshd_config
sed -i 's|PermitRootLogin prohibit-password|PermitRootLogin no|g' /etc/ssh/sshd_config
sudo systemctl restart sshd.service
}

#######################################
#      Ctrl-Alt-Del seq disable       #  
#  Severity: CAT I | Vul ID: V-80957  #
#######################################
crtl_alt_del()
{
sudo mkdir /etc/dconf/db/local.d/
sudo printf '# DoD Stig Vul ID: V-80957\n[org/gnome/settings-daemon/plugins/media-keys]\nlogout="" ' > /etc/dconf/db/local.d/00-disable-CAD
sudo dconf update
}
########################################
#  USB Mounting disabled               #
#  Severity: CAT II | Vul ID: V-75531  #
########################################
usb_mount_disable()
{
sudo echo "install usb-storage /bin/true" >> /etc/modprobe.d/dod_stig.conf
}

#######################################
#             NTP maxpoll             #
# Severity: CAT II | Vul ID: V-75813  #
#######################################
ntp_maxpoll()
{
sudo echo "maxpoll = 17" >> /etc/ntp.conf
sudo systemctl restart ntp
}

#######################################
#        TCP syncookies               #
# Vul ID: V-75869, V-75883, V-75885,  #
# V-75887,                            #
#######################################
sysctl_conf()
{
sudo sed -i 's|#net.ipv4.tcp_syncookies = 1|net.ipv4.tcp_syncookies = 1|g' /etc/sysctl.conf
sudo sed -i 's|#net.ipv4.conf.default.accept_redirects = 0|net.ipv4.conf.default.accept_redirects = 0|g' /etc/sysctl.conf
sudo sed -i 's|#net.ipv4.conf.all.send_redirects = 0|net.ipv4.conf.all.send_redirects = 0|g' /etc/sysctl.conf
sudo sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward = 0|g' /etc/sysctl.conf
sudo printf '\n#DoD STIG Vul ID: V-75883\nnet.ipv4.conf.default.send_redirects=0' >> /etc/sysctl.conf
# Force sysctl changes without reboot
sudo sysctl -p 
}

########################################
#              auditd                  #
#  Vul ID: V-75617,75627, 75629, 75661 #
#  75663, 75665, 75667, 75687, 75859 
########################################
auditd()
{
# Installing auditd deb packages + dependences
sudo dpkg -i deb_packages/libauparse0_2.4.5-1ubuntu2.1_amd64.deb
sudo dpkg -i deb_packages/auditd_2.4.5-1ubuntu2_amd64.deb
sudo dpkg -i deb_packages/libprelude2v5_1.0.0-11.7ubuntu1_amd64.deb
sudo dpkg -i deb_packages/audispd-plugins_2.4.5-1ubuntu2_amd64.deb
#Set Max_log_file_action from Rotate to Syslog
sudo sed -i 's|max_log_file_action = ROTATE|max_log_file_action = SYSLOG|g' /etc/audit/auditd.conf
sudo sed -i 's|disk_full_action = SUSPEND|disk_full_action = HALT|g' /etc/audit/auditd.conf
sudo sed -i 's|disk_full_action = ignore|disk_full_action = SYSLOG|g' /etc/audisp/audisp-remote.conf
sudo sed -i 's|##enable_krb5 = no|enable_krb5 = yes|g' /etc/audisp/audisp-remote.conf
sudo sed -i 's|network_failure_action = stop|network_failure_action = halt|g' /etc/audisp/audisp-remote.conf
sudo printf '\n#DoD STIG Vul ID: V-75859\nnetwork_failure_action = stop' >> /etc/audisp/audisp-remote.conf
# All required audit rules have been consolidated in the audit.rules files
sudo cp files/audit.rules /etc/audit/audit.rules
sudo systemctl restart auditd.service
}

##########################################
#               PKI Packages             #
# Vul ID: V-75903, 75905
##########################################
pki_packages()
{
sudo dpkg -i deb_packages/opensc-pkcs11_0.15.0-1ubuntu1_amd64.deb
sudo dpkg -i deb_packages/libpam-pkcs11_0.6.8-4_amd64.deb
}

############################################
#  /etc/sudoers.d/securityonion-onionsalt  #
#  Vul ID: V-75489	                       #
############################################
sudoers_config()
{
sudo sed -i 's|NOPASSWD|PASSWD|g' /etc/sudoers.d/securityonion-onionsalt
}

###################################
#  Vlock Virtual Console locking  #
#  Vul ID: V-75439                #
###################################
vlock_config()
{
sudo dpkg -i deb_packages/vlock_2.2.2-5_amd64.deb
}
####################################
#    Wuzah/OSSEC Active Response   #
#    STIG Vul ID: V-75487          #
####################################
wuzah_rule()
{
sudo sed -i 's|</ossec_config>||g' /var/ossec/etc/ossec.conf
sudo printf '\n# STIG Vul ID: V-75487\n<command>\n<name>disable-sguild-account</name>\n<executable>disable-sguild-account.sh</executable>\n<expect>user</expect>\n<timeout_allowed>yes</timeout_allowed>\n</command>\n' >> /var/ossec/etc/ossec.conf 
sudo printf '\n<active-response>\n<!-- This response is going to execute the disable-sguild-account.\n- command for every event that fires rule 30414\n- This will disable to users access to kibana/squil/squert\n- to renable it the user must change his/her password using so-user-passwd\n-->\n<command>disable-sguild-account</command>\n<location>local</location>\n<rules_id>30414</rules_id>\n</active-response>\n\n</ossec_config>' >> /var/ossec/etc/ossec.conf
sudo chmod 440 wazuh_ossec/0025-apache_decoders.xml && chown root:root wazuh_ossec/0025-apache_decoders.xml
sudo cp wazuh_ossec/0025-apache_decoders.xml /var/ossec/etc/decoders/0025-apache_decoders.xml
sudo chmod 550 wazuh_ossec/0250-apache_rules.xml && chown root:root wazuh_ossec/0250-apache_rules.xml
sudo cp wazuh_ossec/0250-apache_rules.xml /var/ossec/rules/0250-apache_rules.xml
sudo chmod 755 wazuh_ossec/disable-sguild-account.sh && chown root:root wazuh_ossec/disable-sguild-account.sh
sudo cp wazuh_ossec/disable-sguild-account.sh /var/ossec/active-response/bin/
sudo so-ossec-restart && so-ossec-agent-restart
}

###################
#  Reboot Option  #
###################
reboot_question()
{
echo""
echo "DoD Stigs have been enforeced on this machine.  Some of the changes will require a reboot."
echo ""
echo "Would you like to reboot now? (Y/n)"
read user_reboot_option
if [ ${user_reboot_option,,} != "y" ] ; then
    echo "Please reboot at your ealiest convenience."
    exit
else 
    echo ""
    echo "system is rebooting"
    sudo reboot
fi
}
#################################
#      user/group ownership     #
#  STIG Vul ID's: 75555, 75557  #
#################################
file_ownership()
{
echo ""
echo "Checking filesystem to ensure all files have valid owners and groups"
echo ""
echo "This may take a while."
find / -nogroup >> invalid_user_group 2>/dev/null
find / -nouser  >> invalid_user_group 2>/dev/null

if [ -s invalid_user_group ]; then
   echo ""
   echo "$(<invalid_user_group)"
   echo ""
   echo "The above files are not owned by a valid user or group."
   echo ""
   echo "Would you like to assign root as the user and group now? (Y/n)"
   read user_file_input
   if [ ${user_file_input,,} == "y" ] ; then
      for file in $(cat invalid_user_group); do
          chown root:root $file
      done
   else
      echo "This will reamain a finding until approprate file permissions are assigned to the files listed in the invalid_user_group file"
   fi
fi
}
#################################
#  Where the Magic Happens !!!  #
#################################
welcome_script
login_banner
common_auth
telnet_remove
login.defs
inactive_accounts
inactivity_logout
password_complexity
sshd_conf
crtl_alt_del
usb_mount_disable
ntp_maxpoll
sysctl_conf
auditd
pki_packages
sudoers_config
vlock_config
wuzah_rule
file_ownership
reboot_question
