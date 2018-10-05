import requests, json
from database import Database
import config
import multiprocessing
from multiprocessing.pool import ThreadPool
import time
from logger import Logger

def get_source_data(sourcedb):
    """ get pi source domains """
    """ domain status types: https://docs.pi-hole.net/ftldns/database/#supported-status-types """
    cursor = sourcedb.cursor
    rec = cursor.execute("""
        select domain,count(domain)
        from queries
        group by domain
        order by count(domain) desc;
    """)
    rows = rec.fetchall()
    sourcedb.close()
    return rows

def get_geo_json(domain, ip):
    """ geolocation API """
    geo_res = requests.get(config.GEOLOCATION_API, params = {"apiKey": config.GEOLOCATION_API_KEY, "ip": ip})
    try:
        res_data = geo_res.json()
        metadata = (domain,
                    ip,
                    res_data.get("continent_code", "N/P"),
                    res_data.get("country_code2", "N/P"),
                    res_data.get("latitude", -9999),
                    res_data.get("longitude", -9999),
                    res_data.get("isp", "N/P"))
        return metadata
    except JSONDecodeError:
        pass

def get_refs(domain):
    """ ThreatCrowd API and GeoLoc API """
    res = requests.get(config.THREAT_API, params = {"domain": domain })
    try:
        res_json = res.json()
        votes = res_json.get("votes", None)
        if votes is not None and votes < config.THREAT_THRESHOLD:
            ips = [(domain, d["ip_address"], d["last_resolved"]) for d in res_json["resolutions"] if d["ip_address"] is not "-"]
            ip_geos = [get_geo_json(domain, ip[1]) for ip in ips] # ip[1] for ip in existing tuple list
            hashes = [(domain, f) for f in res_json["hashes"]]
            metadata = [set(ips), set(hashes), set(ip_geos)]
            return metadata
        else:
            return None
    except JSONDecodeError:
        pass

def save_data(targetdb, ips, hashes, ipgeos):
    """ update staging data """
    targetdb.cursor.executemany("""
            insert into ips (parent_domain, ip_address, last_resolved) values (?, ?, ?)
        """, ips)
    targetdb.cursor.executemany("""
            insert into files (parent_domain, hash) values (?, ?)
        """, hashes)
    targetdb.cursor.executemany("""
            insert into ipgeos (parent_domain, ip_address, continent_code, country_code, latitude, longitude, isp) values (?, ?, ?, ?, ?, ?, ?)
        """, ipgeos)
    """ cleanup and commit """
    targetdb.conn.commit()
    targetdb.close()

def process_domains(source_data, targetdb, logger):
    """ Multiprocess ips, file hashes and store in staging """
    try:
        with ThreadPool(multiprocessing.cpu_count()) as p:
            all_metadata = p.map(get_refs, [d[0] for d in source_data])
            clean_metadata = [item for item in all_metadata if item is not None] # filter collected
            """ clean ips """
            list_ips = [next(iter(items), None) for items in clean_metadata for item in items]
            flat_ips = [item for items in list_ips for item in items if item is not None] # flatten dataset
            """ clean hashes """
            list_hashes = [next(iter(items[1:]), None) for items in clean_metadata for item in items]
            flat_hashes = [item for items in list_hashes for item in items if item is not None] # flatten dataset
            """ clean ipgeos """
            list_ipgeos = [next(iter(items[2:]), None) for items in clean_metadata for item in items]
            flat_geos = [item for items in list_ipgeos for item in items if item is not None] # flatten dataset
            """ uniqueness """
            unique_ips = list(set(flat_ips))
            unique_hashes = list(set(flat_hashes))
            unique_ipgeos = list(set(flat_geos))
            save_data(targetdb, unique_ips, unique_hashes, unique_ipgeos)
            p.terminate()
    except Exception as e:
        logger.exception(str(e))
        raise e

if __name__ == '__main__':
    LOGGER = logger = Logger(__name__).get()
    sourcedb = Database(config.PI_DATABASE['db'])
    targetdb = Database(config.STAGING_DATABASE['db'])
    pi_domains = get_source_data(sourcedb)
    start_time = time.time()
    process_domains(pi_domains, targetdb, LOGGER)
    LOGGER.info("--- PiHole staging processed in %s seconds ---" % (time.time() - start_time))
