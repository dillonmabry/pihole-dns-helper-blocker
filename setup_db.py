import sqlite3
import config

""" init seed db and stage table """
def create_connection(db_file):
    """ create a database connection to a SQLite database """
    try:
        conn = sqlite3.connect(db_file)
        conn.execute(
        """
          DROP TABLE IF EXISTS Domains;
        """
        )
        conn.execute(
        """
          CREATE TABLE IF NOT EXISTS Domains
          (
            id INTEGER PRIMARY KEY,
            parent_domain TEXT,
            ip_address TEXT,
            last_resolved DATE
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
