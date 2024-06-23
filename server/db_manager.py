import datetime
import sqlite3

DB_FILE = "defensive.db"

class ClientInfo:
    def __init__(self):
        self.client_id = ""
        self.name = ""
        self.public_key = ""
        self.last_seen = ""
        self.aes_key = ""

class FileInfo:
    def __init__(self):
        self.file_id = ""
        self.file_name = ""
        self.path_name = ""
        self.verified = False

class DB_Manager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
        self.conn.row_factory = sqlite3.Row
        self.init_DB()

    def init_DB(self):
        # create table 'clients' if not exists in the DB
        query = '''CREATE TABLE IF NOT EXISTS clients
         (ID CHAR(16) PRIMARY KEY    NOT NULL,
         Name           VARCHAR(255)  NOT NULL,
         PublicKey      VARCHAR(160),
         LastSeen       DATETIME,
         AESKey         CHAR(16))
        '''
        self.conn.execute(query)

        # create table 'files' if not exists in the DB
        query = '''CREATE TABLE IF NOT EXISTS files
         (ID CHAR(16) PRIMARY KEY    NOT NULL,
         FileName       VARCHAR(255)  NOT NULL,
         PathName       VARCHAR(255),
         Verified       BOOLEAN)
         '''
        self.conn.execute(query)

    def getAllClients(self):
        result_rows = self.conn.execute('SELECT * FROM clients')
        clients = []
        for row in result_rows:
            client = ClientInfo()
            client.client_id = row['ID']
            client.name = row['Name']
            client.public_key = row['PublicKey']
            client.last_seen = row['LastSeen']
            client.aes_key = row['AESKey']
            clients.append(client)
        return clients

    def addClient(self, client_id, name, public_key, aes_key):
        last_seen = datetime.datetime.now()
        query = '''INSERT INTO clients(ID,NAME,PublicKey,LastSeen,AESKey) VALUES(?,?,?,?,?)'''
        self.conn.execute(query, (client_id, name, public_key, last_seen, aes_key))
        self.conn.commit()

    def updateClient(self, client_id, name, public_key, aes_key):
        last_seen = datetime.datetime.now()
        query = '''UPDATE clients SET NAME=?, PublicKey=?, LastSeen=?, AESKey=? WHERE ID=?'''
        self.conn.execute(query, (name, public_key, last_seen, aes_key, client_id))
        self.conn.commit()

    def getAllFiles(self):
        result_rows = self.conn.execute('''SELECT * FROM files''')
        files = []
        for row in result_rows:
            file = FileInfo()
            file.file_id = row['ID']
            file.file_name = row['FileName']
            file.path_name = row['PathName']
            file.verified = row['Verified']
            files.append(file)
        return files

    def addFile(self, file_id, file_name, file_path, verified):
        query = '''INSERT INTO files(ID,FileName,PathName,Verified) VALUES(?,?,?,?)'''
        self.conn.execute(query, (file_id, file_name, file_path, verified))
        self.conn.commit()

    def updateFile(self, file_id, file_name, path_name, verified):
        query = '''UPDATE files SET FileName=?, PathName=?, Verified=? WHERE ID=?'''
        self.conn.execute(query, (file_name, path_name, verified, file_id))
        self.conn.commit()
