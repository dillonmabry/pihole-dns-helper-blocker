#!/bin/bash
sqlite3 pihole-metadata.db <<!
.headers on
.mode csv
.output pihole-metadata.csv
select * from domains;
!
