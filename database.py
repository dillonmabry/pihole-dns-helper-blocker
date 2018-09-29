import sqlite3

""" db class """
class Database:
    """ db init """
    def __init__(self, name=None):
        try:
            self.conn = sqlite3.connect(name)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            print("Connection error: {0}".format(e))

    """ db cleanup """
    def close(self):
        if self.conn:
            self.cursor.close()
            self.conn.close()
