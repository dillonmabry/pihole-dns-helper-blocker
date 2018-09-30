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

def get_refs(domain):
    """ get api results for each request, insert to staging """
    res = requests.get(config.THREAT_API, params = {"domain": domain })
    res_json = res.json()
    votes = res_json.get("votes", None)
    if votes is not None and votes < config.THREAT_THRESHOLD:
        ips = [(domain, d['ip_address'], d['last_resolved']) for d in res_json["resolutions"]]
        hashes = [(domain, f) for f in res_json["hashes"]]
        metadata = [set(ips), set(hashes)]
        return metadata
    else:
        return None

def save_data(targetdb, ips, hashes):
    """ update staging data """
    targetdb.cursor.executemany("""
            insert into ips (parent_domain, ip_address, last_resolved) values (?, ?, ?)
        """, ips)
    targetdb.cursor.executemany("""
            insert into files (parent_domain, hash) values (?, ?)
        """, hashes)
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
            unique_ips = list(set(flat_ips)) # uniqueness
            unique_hashes = list(set(flat_hashes)) # uniqueness
            save_data(targetdb, unique_ips, unique_hashes)
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
