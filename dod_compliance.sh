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



####################
#  Welcome Script  #
####################
welcome_script()
{
cat << EOF 

This script will make the following changes to Security Onion 16.04 in order to meet DoD RMF Requirements:
    - Add DoD login banner (for SSH and Desktop enviroment logins)
    - Lock account after 3 failed login attempts
    - Enforce DoD password complexity (Local accounts and sguil/kibana)

EOF
}

#######################
#  DoD login Banner  #
#######################
login_banner()
{
echo "Adding DoD login Message Banner"
# This will create a SSH login banner
# Move login banner to /etc directory
sudo cp dod_login_banner /etc/dod_login_banner

# Add banner file location to sshd_config
sudo sed -i 's|#Banner /etc/issue.net|Banner /etc/dod_login_banner|g' /etc/ssh/sshd_config
sudo systemctl restart sshd

# This will add a DoD consent splash page for web access
# This only works because Apache2 will load index.html before index.php.  This can be modified in the
# /etc/apache2/mods-enabled/dir.conf
sudo cp dod_index.html /var/www/so/index.html
sudo cp dod_banner.css /var/www/so/css

# DoD consent Splash Page for gnome login.
sudo cp dod_50-gnome.conf /usr/share/lightdm/lightdm.conf.d/50-gnome.conf
}

########################
#  login account lock  #
########################
login_account_lock()
{
echo ""
echo "Setting server accouts to lock for 60 Minutes after 3 failed login attempts."
sudo cp dod_common-auth /etc/pam.d/common-auth
}
#####################
#  Max Login limit  #
#  Vul ID: V-75443  #
#####################
max_login_limit()
{
echo '* hard maxlogins 10' >> /etc/security/limits.conf
}
####################################
#  Password lifetime restrictions  #
####################################
pass_lifetime()
{
# STIG Vul ID: V-75471
sed -i 's|PASS_MIN_DAYS.*|PASS_MIN_DAYS   1|g' /etc/login.defs
sed -i 's|PASS_MAX_DAYS.*|PASS_MAX_DAYS   60|g' /etc/login.defs
}
################################
#  Account Inactivity disable  #
################################
inactive_accounts()
{
# STIG Vul ID: V-75485
useradd -D -f 35
}

###############################
#  Account inactivity logout  #
###############################
# Add inactivity logout IAW V-75441
inactivity_logout()
{
sudo printf '#!/bin/bash\nTMOUT=900\nreadonly TMOUT\nexport TMOUT' > /etc/profile.d/autologout.sh
sudo chmod 755 /etc/profile.d/autologout.sh
}
#############################
#  Set Password Complexity  #
#############################
password_complexity()
{
echo ""
echo "Configuring password Complexity to DoD standard"
sudo cp dod_common-password /etc/pam.d/common-password
sudo dpkg -i libpam-cracklib_1.1.8-3.2ubuntu2_amd64.deb
echo ""
echo "Moving old so-user-add script to /usr/sbin/.so-user-add.bak"
sudo mv /usr/sbin/so-user-add /usr/sbin/.so-user-add.bak
echo ""
echo "Adding new so-user-add script"
sudo cp dod_sguil_password.sh /usr/sbin/so-user-add
sudo chmod 755 /usr/sbin/so-user-add
}

#####################################
#    PermitUserEnv. in sshd.conf    #
# Severity: CAT I| Vul ID: V-75833  #
#####################################
sshd_user_env()
{
printf '# DoD Stig Vul ID: V-75833\nPermitUserEnvironment no' >> /etc/ssh/sshd_config
sudo systemctl restart sshd.service
}

#######################################
#      Ctrl-Alt-Del seq disable       #  
#  Severity: CAT I | Vul ID: V-80957  #
#######################################
crtl_alt_del()
{
mkdir /etc/dconf/db/local.d/
printf '# DoD Stig Vul ID: V-80957\n[org/gnome/settings-daemon/plugins/media-keys]\nlogout="" ' > /etc/dconf/db/local.d/00-disable-CAD
dconf update
}

#  Where the Magic Happens !!!  #
#################################
welcome_script
login_banner
login_account_lock
max_login_limit
inactivity_logout
password_complexity
