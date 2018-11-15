#!/bin/bash
echo "Please enter a password"
read -s user_pass

if [[ ${#user_pass} -ge 15 ]]
then 
    if [[ "$user_pass" =~ [A-Z]{2} ]]
    then
        if [[ "$user_pass" =~ [0-9]{2} ]]
        then
            if [[ "$user_pass" =~ [@#\$%^\&*()_+]{2} ]]
            then
                echo "meets requirements"
            else
                echo "does not meet requirements"
            fi
        else
            echo "no numbers"
        fi
    else
        echo "no upper"
    fi
else
    echo "not long enough"
fi
