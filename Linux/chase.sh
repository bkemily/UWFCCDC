vi ./.bash_profile

ln -s . ./.bash_profile ./pro

. ./pro

-------------------------------------

#!/bin/bash

 

export HISTTIMEFORMAT="%F %T: "

export ISO=isodom.infousa.com

export DMZ=dmz.infousa.com

export TERM=xterm

export HOME=~anthony

 

set -o vi

export PATH=$PATH:./:/bin:/sbin:/usr/bin:/usr/sbin:/usr/openwin/bin:/usr/local/bin:/opt/dell/srvadmin/bin:/usr/local/sbin

TITLEBAR='\[\033]0;\h\007\]'

 

if [ ! -s /tmp/anthony/STRING ]

then

                mkdir /tmp/anthony 2>/dev/null

                        touch /tmp/anthony/STRING 2>/dev/null

fi

 

export PS1="

${TITLEBAR}\

--------------------

UID:    \u

HOST:   $(cat /tmp/anthony/STRING)\h

--------------------

\t: \w/ > "