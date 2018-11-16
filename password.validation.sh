#!/bin/bash -i
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
# Date Created: 2018-11-16
# Date last modified: 2018-11-16
# Purpose: This script will replace the so-user-add script in Security Onion to enforce DoD complient password policies.

#######################
#  User Name function #
#######################
dod_user_name()
{
echo ""
echo "Enter the Username of the new user that will be granted privileges to connect to Sguil/Squert/Kibana"
read -p "Username: " USER_NAME

if [[ "$USER_NAME" =~ [^a-zA-Z0-9] ]]; then
    echo ""
    echo "The Username must contain only alpha-numeric characters."
    dod_user_name
fi
}
################################
#  DoD user password function  #
################################
dod_user_pass()
{
echo "Please enter a password following DoD guidance."
read -p -s "User Password: " USER_PASS
#Check if the password Length is greater or equal to 15 characters
if [[ ${#USER_PASS} -ge 15 ]]; then
    # Check if the password has at least 2 upper case letters
    if [[ "$USER_PASS" =~ [A-Z]{2} ]]; then
        # Check if the password has at least 2 digits
        if [[ "$USER_PASS" =~ [0-9]{2} ]]; then
            # Check if the password has at least 2 special characters
            if [[ "$USER_PASS" =~ [!\@#\$%^\&*()_+]{2} ]]; then
                dod_user_pass_verify
            else
                echo "Please use at least 2 of the following special characters !@#$%^&*()_+ "
                dod_user_pass
            fi
        else
            echo "Your password must include 2 numbers."
            dod_user_pass
        fi
    else
        echo "Your password must include 2 upper case characters."
        dod_user_pass
    fi
else
    echo "Your password must be at least 15 characters in length."
    dod_user_pass
fi
}

#############################################
#  DoD user password verification function  #
#############################################
dod_user_pass_verify()
{
echo "Please verify password."
read -p -s "verify: " USER_PASS
#Check if the password Length is greater or equal to 15 characters
if [[ ${#USER_PASS_VERIFY} -ge 15 ]]; then
    # Check if the password has at least 2 upper case letters
    if [[ "$USER_PASS_VERIFY" =~ [A-Z]{2} ]]; then
        # Check if the password has at least 2 digits
        if [[ "$USER_PASS_VERIFY" =~ [0-9]{2} ]]; then
            # Check if the password has at least 2 special characters
            if [[ "$USER_PASS_VERIFY" =~ [!\@#\$%^\&*()_+]{2} ]]; then
                dod_pass_compare
            else
                echo "Please use at least 2 of the following special characters !@#$%^&*()_+ "
                dod_user_pass_verify
            fi
        else
            echo "Your password must include 2 numbers."
            dod_user_pass_verify
        fi
    else
        echo "Your password must include 2 upper case characters."
        dod_user_pass_verify
    fi
else
    echo "Your password must be at least 15 characters in length."
    dod_user_pass_verify
fi
}

################################
#  Compare Passwords Function  #
################################
# Check passwords to see if they are the same.
dod_pass_compare()
{
if [ "USER_PASS" == "USER_PASS_VERIFY" ]; then 
    user_add_sguild
else 
    echo ""
    echo "Your passwords do not match."
    dod_user_pass
fi
}

#################################
#  Add user to sguild function  #
#################################
user_add_sguild()
{
/usr/sbin/sguild-add-user $USER_NAME $USER_PASS >/dev/null 2>&1
if [ "${?}" -ne 0 ]; then
    echo "$USER_NAME could not be added."
else
    echo "$USER_NAME was successfully added."
fi
}

#########################
#  Magic happens below  #
#########################
dod_user_name
dod_user_pass
