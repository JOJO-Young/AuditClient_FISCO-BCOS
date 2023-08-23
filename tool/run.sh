#!/bin/bash

function usage()
{
    echo " Usage : "
    echo "   bash run.sh deploy"
    echo "   bash run.sh save hash ctID flowStartSec"
    echo "   bash run.sh verify hash ctID flowStartSec "
    echo "   bash run.sh get ctID flowStartSec"
    echo "   bash run.sh watch filePath"
    exit 0
}
case $1 in
     deploy)
             [ $# -lt 1 ] && { usage; }
             ;;
     save)
             [ $# -lt 4 ] && { usage; }
             ;;
     verify)
             [ $# -lt 4 ] && { usage; }
             ;;
     get)
             [ $# -lt 3 ] && { usage; }
             ;;
     watch)
             [ $# -lt 2 ] && { usage; }
             ;;
     *)
         usage
             ;;
     esac

     java -Djdk.tls.namedGroups="secp256k1" -cp 'apps/*:conf/:lib/*' org.com.fisco.AuditClient $@