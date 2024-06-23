import os
import struct
import binascii
import shortuuid

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from base64 import b64decode, b64encode

from db_manager import *

PORT_INFO = "port.info"
FILE_STORAGE = "./file_storage/"

SERVER_VERSION = 3
REQUEST_HEADER_SIZE = 23
RESPONSE_HEADER_SIZE = 7


REQUEST_CODE_REGISTER = 1025
REQUEST_CODE_SENDING_PUBKEY = 1026
REQUEST_CODE_RELOGIN = 1027
REQUEST_CODE_SENDING_FILE = 1028
REQUEST_CODE_VALID_CRC = 1029
REQUEST_CODE_INVALID_CRC = 1030
REQUEST_CODE_LAST_INVALID_CRC = 1031

RESPONSE_CODE_REGISTER_SUCCESS = 2100
RESPONSE_CODE_ALEADY_EXIST = 2101
RESPONSE_CODE_SENDING_ENCKEY = 2102
RESPONSE_CODE_FILE_ACCEPTED = 2103
RESPONSE_CODE_MESSAGE_CONFIRMED = 2104
RESPONSE_CODE_RELOGIN_CONFIRMED = 2105
RESPONSE_CODE_RELOGIN_REJECTED = 2106
RESPONSE_CODE_GENERAL_ERROR = 2107


def encryptAESKey(public_key, aes_key):  # encrypt plain text using RSA key
    decoded_public_key = b64decode(public_key)
    public_rsa_key = RSA.importKey(decoded_public_key)
    cipher = PKCS1_v1_5.new(public_rsa_key)
    encrypted_aes_key = cipher.encrypt(aes_key)
    return b64encode(encrypted_aes_key)


def decryptTextByAES(cipher_text, aes_key):  # decrypt message using AES key
    decoded_aes_key = b64decode(aes_key)
    cipher = AES.new(decoded_aes_key, AES.MODE_CBC, AES.block_size * b'\x00')
    decoded_text = b64decode(cipher_text)
    aes_decrypted_text = cipher.decrypt(decoded_text)
    return aes_decrypted_text

class Request:
    def __init__(self):
        self.client_id = ""
        self.version = 0
        self.code = 0
        self.payload_size = 0

    def unpackRequestHeader(self, buf):
        arr = bytearray(buf)
        self.client_id = arr[0:16].decode("utf-8")
        self.version = struct.unpack("<B", arr[16:17])[0]
        self.code = struct.unpack("<H", arr[17:19])[0]
        self.payload_size = struct.unpack("<I", arr[19:23])[0]


class Response:
    def __init__(self):
        self.version = SERVER_VERSION
        self.code = 0
        self.payload_size = 0

    def makeHeader(self):
        result = bytes()
        result += struct.pack("<B", self.version)
        result += struct.pack("<H", self.code)
        result += struct.pack("<I", self.payload_size)
        return result


class HandleClient:
    def __init__(self, conn):
        self.payload_array = None
        self.socket = conn
        self.request = Request()
        self.payload_buffer = bytes()
        self.retry_receive = False
        self.db = DB_Manager()
        self.login_client = ClientInfo()
        self.file_info = FileInfo()
        self.aes_key = b64encode(os.urandom(16))    # generate random key and encode it by Base64

    def respondToRequest(self):
        if self.request.code == REQUEST_CODE_REGISTER:
            return self.processRegisterRequest()
        elif self.request.code == REQUEST_CODE_RELOGIN:
            return self.processReloginRequest()
        elif self.request.code == REQUEST_CODE_SENDING_PUBKEY:
            return self.processSendingPubkeyRequest()
        elif self.request.code == REQUEST_CODE_SENDING_FILE:
            return self.processSendingFileRequest()
        elif self.request.code == REQUEST_CODE_VALID_CRC:
            return self.processValidCRCRequest()
        elif self.request.code == REQUEST_CODE_LAST_INVALID_CRC:
            return self.processLatestInvalidCRCRequest()
        elif self.request.code == REQUEST_CODE_INVALID_CRC:
            return self.processInvalidCRCRequest()
        else:
            return self.sendInternalErrorRespond()

    def receivePayload(self, request, payload_buf):
        self.request = request
        self.payload_buffer = payload_buf
        return self.respondToRequest()

    def processReloginRequest(self):
        print("-> logging in now...")
        response = Response()
        #---- extract client client_name from payload -----
        client_name = self.payload_buffer.decode("utf-8").replace('\x00', '')

        #---- check if client exist on db
        is_exist = False
        all_clients = self.db.getAllClients()
        for client in all_clients:
            if client.name == client_name and client.client_id == self.request.client_id:
                is_exist = True  #same client_name exist, client is is_exist already
                self.login_client = client
                break
        if is_exist:
            #---------- send aes key to client
            response.code = RESPONSE_CODE_RELOGIN_CONFIRMED
            self.login_client.aes_key = self.aes_key

            # encrypt aes key using pubkey
            aes_key_rsa_encoded = encryptAESKey(self.login_client.public_key, self.aes_key)

            # response with aes key
            response.payload_size = 16 + len(aes_key_rsa_encoded)
            payload = self.login_client.client_id.encode()
            payload += aes_key_rsa_encoded

            self.socket.send(response.makeHeader())
            self.socket.send(payload)

            # set client info of the handle
            self.db.updateClient(self.login_client.client_id,
                                 self.login_client.name,
                                 self.login_client.public_key,
                                 self.login_client.aes_key)
            print("-> logged in successfully")
            return True
        else:
            # if not is_exist, reject request of login
            response.code = RESPONSE_CODE_RELOGIN_REJECTED
            response.payload_size = len(self.request.client_id)
            self.socket.send(response.makeHeader())
            self.socket.send(self.request.client_id.encode())
            print("-> login failed. not registered client.")
            return False

    def processRegisterRequest(self):
        print("-> registering client...")
        response = Response()
        #---- extract client name from payload -----
        new_name = self.payload_buffer.decode("utf-8")
        new_name = new_name.replace('\x00', '')

        is_exist = False
        # check if client exist in DB
        all_clients = self.db.getAllClients()
        print("here")
        for client in all_clients:
            if client.name == new_name:
                is_exist = True
                break

        if is_exist:
            response.code = RESPONSE_CODE_ALEADY_EXIST
            self.socket.send(response.makeHeader())
            print("-> already exist same name")
            return False
        else:
            # ---- add new client to DB ----
            # genarate client id by UUID
            client_id = shortuuid.ShortUUID().random(length=16)
            # add new client
            self.db.addClient(client_id, new_name, "", "")
            #------ response to client registering result -----
            response.code = RESPONSE_CODE_REGISTER_SUCCESS
            response.payload_size = len(client_id)
            self.socket.send(response.makeHeader())
            self.socket.send(bytes(client_id, "utf-8"))
            #------- update client info -----
            self.login_client.client_id = client_id
            self.login_client.name = new_name
            print("-> client registered successfully")
            return True

    def processSendingFileRequest(self):
        print("-> arrived file from client, processing it ...")
        respond = Response()
        # extract info from payload
        payload_array = bytearray(self.payload_buffer)
        file_length = struct.unpack("<I", payload_array[0:4])[0]
        temp = struct.unpack("=255s", payload_array[4:259])[0]
        file_name = temp.decode("utf-8").replace('\x00', '')
        data = payload_array[259:].decode("utf-8")
        data = data.replace('\x00', '')
        # decrypt data by aes key
        contents = bytearray(decryptTextByAES(data, self.aes_key))

        # Check CRC code
        crc = binascii.crc32(contents[0:file_length])

        # create new file with accepted file name and write content
        file_path = FILE_STORAGE + file_name
        with open(file_path, "wb") as outfile:
            outfile.write(contents[0:file_length])
        print("-> file saved on storage")

        if not self.retry_receive:
            self.file_info.file_id = shortuuid.ShortUUID().random(length=16)
        self.file_info.file_name = file_name
        self.file_info.verified = False

        respond.code = RESPONSE_CODE_FILE_ACCEPTED
        respond.payload_size = 16 + 4 + 255 + 4

        payload = bytes()
        payload += struct.pack("=16s", str.encode(self.login_client.client_id))
        payload += struct.pack("<I", file_length)
        payload += struct.pack("=255s", str.encode(file_name))
        payload += struct.pack(">I", crc)

        # send respond
        self.socket.send(respond.makeHeader())
        self.socket.send(payload)
        print("-> sending crc of file...")

        # add new file
        if not self.retry_receive:
            self.db.addFile(self.file_info.file_id, self.file_info.file_name,
                            FILE_STORAGE, self.file_info.verified)
        return True

    def processSendingPubkeyRequest(self):
        respond = Response()
        # parse payload
        payload_array = bytearray(self.payload_buffer)
        name = payload_array[0:255].decode("utf-8")
        name = name.replace('\x00', '')
        pubkey = payload_array[255:].decode("utf-8")
        pubkey = pubkey.replace('\x00', '')

        # check if the request client is logged in
        if self.login_client.name == name and self.login_client.client_id == self.request.client_id:
            self.login_client.public_key = pubkey
            self.login_client.aes_key = self.aes_key
            #---------- send respond ----
            respond.code = RESPONSE_CODE_SENDING_ENCKEY
            aes_key_rsaencoded = encryptAESKey(pubkey, self.aes_key) # encrypt public key by aes key
            respond.payload_size = 16 + len(aes_key_rsaencoded)
            payload = self.login_client.client_id.encode()
            payload += aes_key_rsaencoded
            self.socket.send(respond.makeHeader())
            self.socket.send(payload)
            #----------- update client info ---------
            self.db.updateClient(self.login_client.client_id,
                                 self.login_client.name,
                                 self.login_client.public_key,
                                 self.login_client.aes_key)
            print("-> Public Key received, sent AES key back to client")
            return True
        else:
            # error respond
            self.sendInternalErrorRespond()
            print("-> Unknown Client")
            return False



    def processValidCRCRequest(self):
        print("-> valid crc received")

        respond = Response()
        # extract info from payload
        payload_array = bytearray(self.payload_buffer)
        file_name = payload_array[0:].decode("utf-8")
        file_name = file_name.replace('\x00', '')
        # check if valid request
        if self.login_client.client_id == self.request.client_id \
                and self.file_info.file_name == file_name:
            # send respond
            respond.code = RESPONSE_CODE_MESSAGE_CONFIRMED
            respond.payload_size = 16
            payload = bytes()
            payload += struct.pack("=16s", str.encode(self.login_client.client_id))
            # send respond
            self.socket.send(respond.makeHeader())
            self.socket.send(payload)

            # update file info
            self.file_info.verified = True
            self.db.updateFile(self.file_info.file_id, self.file_info.file_name,
                               FILE_STORAGE, self.file_info.verified)
            self.retry_receive = False
            print("-> file received successfully.\n")
            return False
        else:
            self.sendInternalErrorRespond()
            print("-> error while receiving file")
            return False

    def processLatestInvalidCRCRequest(self):
        print("-> client says last CRC tries...")
        respond = Response()
        # extract file name from payload
        self.payload_array = bytearray(self.payload_buffer)
        file_name = self.payload_array.decode("utf-8")
        # check if client is logged in
        if self.login_client.client_id == self.request.client_id:
            if self.file_info.file_name == file_name:
                self.retry_receive = False
                respond.code = RESPONSE_CODE_MESSAGE_CONFIRMED
                self.socket.send(respond.makeHeader())
        print("-> abort file receiving.\n")
        return False

    def processInvalidCRCRequest(self):
        print("-> client says CRC mismatched")
        respond = Response()
        # parse payload
        self.payload_array = bytearray(self.payload_buffer)
        file_name = self.payload_array.decode("utf-8")
        # check if client is logged in
        if self.login_client.client_id == self.request.client_id:
            if self.file_info.file_name == file_name:
                self.retry_receive = True
        return True

    def sendInternalErrorRespond(self):
        respond = Response()
        respond.code = RESPONSE_CODE_GENERAL_ERROR
        self.socket.send(respond.makeHeader())
        return False

    def closeConnection(self):
        self.socket.close()