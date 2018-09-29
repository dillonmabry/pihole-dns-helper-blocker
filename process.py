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
        sub_domains = [(domain, d['ip_address'], d['last_resolved']) for d in res_json["resolutions"]]
        return set(sub_domains)
    else:
        return ["None"]

def save_data(targetdb, sub_domains):
    """ update staging data """
    targetdb.cursor.executemany("""
            insert into Domains (parent_domain, ip_address, last_resolved) values (?, ?, ?)
        """, sub_domains)
    """ cleanup and commit """
    targetdb.conn.commit()
    targetdb.close()

def process_domains(source_data, targetdb, logger):
    """ Multiprocess subdomains and store in staging """
    try:
        with ThreadPool(multiprocessing.cpu_count()) as p:
            all_domains = p.map(get_refs, [d[0] for d in source_data])
            flat_results = [item for items in all_domains for item in items]
            flat_domains = [result for result in flat_results if result is not "None"]
            save_data(targetdb, flat_domains) # Flatten results from multi
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
