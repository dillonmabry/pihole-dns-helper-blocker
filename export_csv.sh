#!/bin/bash
# Export table as csv
sqlite3 pihole-metadata.db <<!
.headers on
.mode csv
.output $1.csv
select * from $1;
!
