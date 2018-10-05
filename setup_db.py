import sqlite3
import config

""" init seed db and stage table """
def create_connection(db_file):
    """ create a database connection to a SQLite database """
    try:
        # ips
        conn = sqlite3.connect(db_file)
        conn.execute(
        """
          DROP TABLE IF EXISTS ips;
        """
        )
        conn.execute(
        """
          CREATE TABLE IF NOT EXISTS ips
          (
            id INTEGER PRIMARY KEY,
            parent_domain TEXT,
            ip_address TEXT,
            last_resolved DATE
          );
        """
        )
        # ip geolocation
        conn.execute(
        """
          DROP TABLE IF EXISTS ipgeos;
        """
        )
        conn.execute(
        """
          CREATE TABLE IF NOT EXISTS ipgeos
          (
            id INTEGER PRIMARY KEY,
            parent_domain TEXT,
            ip_address TEXT,
            continent_code TEXT,
            country_code TEXT,
            latitude REAL,
            longitude REAL,
            isp TEXT
          );
        """
        )
        # file hashes
        conn.execute(
        """
          DROP TABLE IF EXISTS files;
        """
        )
        conn.execute(
        """
          CREATE TABLE IF NOT EXISTS files
          (
            id INTEGER PRIMARY KEY,
            parent_domain TEXT,
            hash TEXT
          );
        """
        )
        conn.close()
    except sqlite3.Error as e:
        print("Error seeding database and staging table: {0}".format(e))
    finally:
        conn.close()

if __name__ == '__main__':
    create_connection(config.STAGING_DATABASE["db"])
