#! /bin/bash

# his is your second bash script. In this one, you prompt
# the user for input, place the nput in a variable, and
# display the variable contents in a string

echo "What is you name?"

read name

echo "Wahat chapter are you on in Linux Basics for Hackers?"

read chapter

echo "Welcome" $name " to Chapter" $chapter " of Linux Basics for Hackers!"