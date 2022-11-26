#!/bin/bash

AUDIT_CSV=""

SERVER="127.0.0.1"
PORT="8053"
FAIL_ONLY=0
HELP=0


# parse options
while [ -n "$1" ]; do
    case "$1" in
            -s|--server) SERVER="$2"; shift;;
            -p|--port) PORT="$2"; shift;;
            -f|--fail-only) FAIL_ONLY=1;;
            -h|--help) HELP=1; break;;
            -*)
                echo "Invalid option: $1" >&2
                exit 1
            ;;
            *) 
                if [ "$AUDIT_CSV" = "" ]; then
                    AUDIT_CSV="$1"
                else
                    echo "duplicate audit $1" >&2
                    exit 1
                fi
            ;;
    esac
    shift;
done

help_doc() {
	cat <<-EOF

	Usage: $0 [-s <server>] [-p <port>] <audit_csv>

	options:
			-s | --server           The server address (default: 127.0.0.1)
			-p | --port             The server port (default: 8053)
			-f | --fail-only        Only replay fails
			-h | --help             display this help

	EOF
	exit 1
}

if [ $HELP -gt 0 ]; then
    help_doc
fi

echo "#######################################"
echo "Input file: $AUDIT_CSV"
echo "Server address: $SERVER"
echo "Server port: $PORT"

if [ $FAIL_ONLY -gt 0 ]; then
    echo "Filter: Only replay fails"
fi

echo "#######################################"
# exit 0

###################

FIRST_LINE=1
LAST_TIME=0

[ ! -f $AUDIT_CSV ] && { echo "$AUDIT_CSV file not found"; exit 99; }

while IFS=, read -r ID TIMESTAMP CLIENT NAME TYPE ELAPSED SPEED STATE RESULT
do
    if [ $FIRST_LINE -eq 1 ]; then # skip header
        FIRST_LINE=0
        continue
    fi

    if [ $FAIL_ONLY -gt 0 ]; then
        if [ "$STATE" = "success" ]; then
            continue
        fi
    fi

    if [ $LAST_TIME -gt 0 ]; then
        INTERVAL=$(($TIMESTAMP-$LAST_TIME))
        if [ $INTERVAL -gt 0 ]; then
            sleep $INTERVAL
        fi
    fi

    dig @$SERVER -p $PORT $TYPE $NAME

    LAST_TIME=$TIMESTAMP
done < "$AUDIT_CSV"
