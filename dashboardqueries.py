import time
import psycopg2
import json
_author_ = 'Michael Clark'
_project_ = 'Safe Networking'

conn = psycopg2.connect("dbname='safenetworking' user='postgres' host='127.0.0.1' password=safeNETWORKING")
cur = conn.cursor()

cur.execute(
"""create table if not exists dashboard (malwarefamily text, countm text, threattype text, counttt text, severity text, counts text, srcip text, countsrcip text, dstip text, countuniquesrc text, domain text, count text)"""
)

conn = psycopg2.connect("dbname='safenetworking' user='postgres' host='127.0.0.1' password=safeNETWORKING")
cur = conn.cursor()

cur.execute(
    """SELECT "domain", count(*) as count from snuniquedomains group by "domain" order by count desc limit 25"
)
conn.commit()
cur.execute(
    """SELECT "Severity", count(*) as count from sn1dnseventsraw group by "Severity" """
)
conn.commit()
cur.execute(
    """SELECT "Threat/Content Name", count(*) as count from sn1dnsthreatname where \
    "Threat/Content Name" != '' and "Threat/Content Name" != '""' group by \ 
    "Threat/Content Name" order by count desc limit 25 """
)
conn.commit()
cur.execute(
    """SELECT "Threat/Content Type", count(*) as count from sn1dnseventsraw group \
    by "Threat/Content Type" order by count desc limit 25"""
)
conn.commit()
cur.execute(
    """SELECT count(distinct "Source address") as count from sn1dnseventsraw"""
)
conn.commit()
cur.execute(
    """SELECT "Source address", count(*) as count from sn1dnseventsraw group by \
    "Source address" order by count desc limit 25"""
)
conn.commit()
cur.execute(
    """SELECT "Destination address", count(*) as count from sn1dnseventsraw group \
    by "Destination address" order by count desc limit 25"""
)
conn.commit()  
cur.execute(
    """SELECT "tags", count(*) as count from connectionreport2 where "tags" != '' \
    group by "tags" order by count desc limit 25"""
)
conn.commit()
conn.close()
