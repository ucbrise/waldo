#!/bin/bash

if [ $# -lt 1 ]
then
    echo "Script expects network interface"
    exit
fi

if [ "$1" = "S" ]
then
    sudo tc qdisc del dev lo root
fi

if [ "$1" = "M" ]
then
    sudo tc qdisc del dev eth0 root
fi
