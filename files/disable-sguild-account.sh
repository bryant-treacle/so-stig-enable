#!/bin/bash
# Uses /usr/bin/squild to lock user account after 3 failed login attempst within 60 seconds
# Author: Bryant Treacle
# Last Modified: 6 Dec 18

ACTION=$1
USER_NAME=$2
IP=$3

/usr/bin/sguild -disableuser "${USER_NAME}"
