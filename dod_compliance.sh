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
    - Add DoD login banner
    - Lock account after 3 failed login attempts    

EOF
}

#######################
#  DoD login Banner  #
#######################
login_banner()
{
echo "Adding DoD login Message Banner"
# Move login banner to /etc directory
sudo cp dod_login_banner /etc/dod_login_banner

# Add banner file location to sshd_config
sudo sed -i 's|#Banner /etc/issue.net|Banner /etc/dod_login_banner|g' /etc/ssh/sshd_config
sudo systemctl restart sshd
}

########################
#  login account lock  #
########################
login_account_lock()
{
echo ""
echo "Setting server accouts to lock for 60 Minutes after 3 failed login attempts."
sudo cp common-auth /etc/pam.d/common-auth
}

#############################
#  Set Password Complexity  #
#############################
password_complexity()
{
echo ""
echo "Configuring password Complexity to DoD standard"
sudo cp common-password /etc/pam.d/common-password
sudo dpkg -i libpam-cracklib_1.1.8-3.2ubuntu2_amd64.deb
}

#################################
#  Where the Magic Happens !!!  #
#################################
welcome_script
login_banner
login_account_lock
password_complexity
