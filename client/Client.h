#include <iostream>
#include <string>
#include <cstdint>
#include <fstream>
#include <WinSock2.h>
#include <WS2tcpip.h>


#include "rsa.h"
#include "base64.h"
#include "osrng.h"

// Crypto++ libraries
#include "modes.h"
#include "hex.h"
#include "crc.h"
#include "files.h"

using namespace std;
using namespace CryptoPP;

#pragma comment (lib, "Ws2_32.lib")

#define CLIENT_VERSION		3
#define MAX_RETRY_COUNT		4

#define FILE_CLIENT_INFO "me.info"
#define FILE_TRANSFER_INFO "transfer.info"

// constants for message code
#define REQUEST_CODE_REGISTER 1025
#define REQUEST_CODE_SEND_PUBKEY	1026
#define REQUEST_CODE_RELOGIN		1027
#define REQUEST_CODE_SEND_FILE		1028
#define REQUEST_CODE_CRC_OK			1029
#define REQUEST_CODE_CRC_MISMATCHED	1030
#define REQUEST_CODE_LAST_CRC_TRY	1031

#define RESPONSE_CODE_REGISTER_SUCCESS	2100
#define RESPONSE_CODE_ALEADY_EXIST		2101
#define RESPONSE_CODE_SENDING_ENCKEY	2102
#define RESPONSE_CODE_FILE_UPLOADED		2103
#define RESPONSE_CODE_MESSAGE_CONFIRMED	2104
#define RESPONSE_CODE_RELOGIN_CONFIRMED	2105

#pragma pack(push, 1)
struct  ReqHead{
	char client_id[16];
	uint8_t client_version;
	uint16_t code;
	uint32_t payload_size;
} ;
#pragma pack(pop)

struct Request {
	char* payload;
	ReqHead head_info;
};

#pragma pack(push, 1)
struct  RespHead{
	uint8_t server_version;
	uint16_t code;
	uint32_t payload_size;
} ;
#pragma pack(pop)

class Client
{
public:
	Client();
	~Client();
	
	bool initializeClient();	
	void processUploadingTask();

	// Crypto++
	
	
private:
	string client_id;
	string client_name;	
	SOCKET client_socket;
	string sendfile_name;
	string server_ip;
	int server_port;
	bool register_status;

	string public_key;
	string private_key;
	string AES_key;

	bool connectToServer();
	bool loadTransferInfo(string file_path);
	bool loadClientInfo(string file_path);

	ReqHead makeReqHeader(int code, uint32_t payload_size);
	void sendRequest(Request req);
	bool sendReloginRequest();
	bool sendRegisterMessage();
	bool sendFile();
	bool sendCRC(bool crc_status, int ret_cnt);
	bool sendPublicKey();


	char* receivePayload(RespHead& resp);
	bool receiveReloginResponse();
	bool recevieRegisterResponse();
	bool receiveFileAcceptedResponse();
	bool receiveConfirmMessage(int ret_cnt);	
	bool receiveAESkey();

	//-------- Encryption -----------
	void InitializeKeys();	// generate public key and generate key
	string decryptTextByRSA(char* cypher_text, string private_key);  // decrypt b64 encoded cypher text using RSA key
	string encryptTextByAES(char* plain_text, size_t plain_length, string aes_key_b64encoded);	// Encrypt text using AES
	string getCRC32(string file_name);	
};




