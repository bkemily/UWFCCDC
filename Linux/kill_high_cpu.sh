#!/bin/bash
ps -eo pid,pcpu,comm --sort=-%cpu | awk '$2>80 {print $1}' | xargs kill -9
