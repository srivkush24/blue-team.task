#!/usr/bin/env bash
# detect.sh - decrypts a Vigenere encrypted web log and looks for attacks
#
# usage:  ./detect.sh access.log.enc [key]
# key is optional, MAYDAY is used if you don't give one
# set VERBOSE=1 to also see first/last time of each attack
#
# exit code: 1 = attack found, 0 = nothing found, 2 = bad usage

FILE="$1"
KEY="${2:-MAYDAY}"

if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
    echo "usage: $0 <encrypted log file> [key]" >&2
    exit 2
fi

awk -v key="$KEY" -v verbose="${VERBOSE:-0}" '
BEGIN {
    UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LOW = "abcdefghijklmnopqrstuvwxyz"
    key = toupper(key)
    klen = length(key)
}

{
    # step 1: decrypt the line
    # key starts again from the first letter on every line,
    # and only letters use up a key character
    line = ""
    k = 0
    for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1)
        if ((p = index(UP, c)) > 0) {
            shift = index(UP, substr(key, k % klen + 1, 1)) - 1
            line = line substr(UP, (p - 1 - shift + 26) % 26 + 1, 1)
            k++
        } else if ((p = index(LOW, c)) > 0) {
            shift = index(UP, substr(key, k % klen + 1, 1)) - 1
            line = line substr(LOW, (p - 1 - shift + 26) % 26 + 1, 1)
            k++
        } else {
            line = line c
        }
    }

    # step 2: pull out ip, time and status code
    split(line, parts, " ")
    ip = parts[1]

    ts = ""
    if (match(line, /\[[^]]+\]/))
        ts = substr(line, RSTART + 1, RLENGTH - 2)

    split(line, quoted, "\"")
    split(quoted[3], after, " ")
    status = after[1]

    # step 3: check the three rules

    # brute force: count the 401 responses per ip
    if (status == "401") {
        bf[ip]++
        if (!(ip in bf_first)) bf_first[ip] = ts
        bf_last[ip] = ts
    }

    # sql injection (ignoring upper/lower case)
    low = tolower(line)
    if (low ~ /drop table|or 1=1|or \0471\047=\0471\047/) {
        sq[ip]++
        if (!(ip in sq_first)) sq_first[ip] = ts
        sq_last[ip] = ts
    }

    # directory traversal
    if (line ~ /\.\.\//) {
        dt[ip]++
        if (!(ip in dt_first)) dt_first[ip] = ts
        dt_last[ip] = ts
    }
}

END {
    found = 0

    # brute force needs 5 or more failed logins
    for (ip in bf) {
        if (bf[ip] >= 5) {
            printf "[ALERT] Brute force from %s (%d failed logins)\n", ip, bf[ip]
            if (verbose) printf "        first: %s  last: %s\n", bf_first[ip], bf_last[ip]
            found = 1
        }
    }

    for (ip in sq) {
        printf "[ALERT] SQL injection from %s (%d attempts)\n", ip, sq[ip]
        if (verbose) printf "        first: %s  last: %s\n", sq_first[ip], sq_last[ip]
        found = 1
    }

    for (ip in dt) {
        printf "[ALERT] Directory traversal from %s (%d attempts)\n", ip, dt[ip]
        if (verbose) printf "        first: %s  last: %s\n", dt_first[ip], dt_last[ip]
        found = 1
    }

    exit found
}' "$FILE"

exit $?
