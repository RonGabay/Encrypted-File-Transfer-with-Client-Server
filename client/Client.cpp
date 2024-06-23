#include "Client.h"

vector<string> split(string str, char del) {
	vector<string> tokens = vector<string>();
	// declaring temp string to store the curr "word" upto del
	string temp = "";
	stringstream token_stream;
	bool is_in = false;
	for (unsigned int i = 0; i <= str.length(); i++) { // iterate all characters in input string 'str'

		if (str[i] == del) {
			// Every meet delimiter, push token into vector and clear token string
			tokens.push_back(token_stream.str());
			token_stream.str("");
			continue;
		}
		token_stream << str[i];     // add every character into token string
	}
	tokens.push_back(token_stream.str());
	return tokens;
}

Client::Client()
{
	server_port = 1234;  // default port, it will be updated when load info from client
	client_socket = NULL;
	register_status = false;
}

Client::~Client()
{
	// close the socket when exit program
	if (shutdown(client_socket, SD_BOTH) == SOCKET_ERROR) {
		cout << "===> error while shutdown" << endl;
		closesocket(client_socket);
		WSACleanup();
	}
}

bool Client::connectToServer()
{
	// Check WSA status
	WSADATA wsa_data;
	int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (wsa_result != 0) {
		cout << "==> error while WSAStartup";
		return false;
	}
	client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	SOCKADDR_IN addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	inet_pton(AF_INET, server_ip.c_str(), &(addr.sin_addr));

	if (connect(client_socket, (SOCKADDR*)&addr, sizeof(addr)) == 0) {
		cout << "==> connected to server " << server_ip << ":" << server_port << endl;
		return true;
	}
	else {
		cout << "==> connection failed to " << server_ip << ":" << server_port << endl;
		closesocket(client_socket);
		WSACleanup();
	}
	return false;
}

bool Client::loadTransferInfo(string file_path)
{
	
	string line;
	ifstream infile(file_path);
	if (infile.is_open()) {
		if (getline(infile, line)) { // read ip and port
			vector<string> ip_port = split(line, ':');
			if (ip_port.size() == 2) {
				server_ip = ip_port[0];
				server_port = stoi(ip_port[1]);
				if (getline(infile, client_name)) {
					if (getline(infile, sendfile_name)) {
						cout << "==> loaded transter Info from file" << endl;
						return true;
					}
				}
			}				
		}
	}
	cout << "==> error while loading of transfer Info" << endl;

	return false;
}

bool Client::loadClientInfo(string file_path)
{
	ifstream infile(file_path);
	if (infile.is_open()) {
		if (getline(infile, client_name)) {
			if (getline(infile, client_id)) {
				if (getline(infile, private_key)) {
					cout << "==> loaded Client Info from file" << endl;
					register_status = true;
					return true;
				}
			}
		}
	}
	cout << "==> error while loading of client Info" << endl;
		
	return false;
}

ReqHead Client::makeReqHeader(int req_code, uint32_t payload_size)
{
	ReqHead req_head_info = ReqHead();
	memcpy(req_head_info.client_id, client_id.c_str(), 16);
	req_head_info.client_version = CLIENT_VERSION;
	req_head_info.code = req_code;
	req_head_info.payload_size = payload_size;

	return req_head_info;
}

void Client::sendRequest(Request req)
{
	int header_size = (int)sizeof(ReqHead) + 1;
	char* header_buffer = new char[header_size + 1];
	memcpy(header_buffer, (char*)&req.head_info, sizeof(ReqHead));

	send(client_socket, header_buffer, header_size, SOCK_STREAM);
	if (req.head_info.payload_size != 0 && req.payload != NULL)
		send(client_socket, req.payload, req.head_info.payload_size + 1, SOCK_STREAM);

	delete[] header_buffer;
}

bool Client::sendReloginRequest()
{
	cout << "==> loggin in to server..." << endl;

	ReqHead req_head_info = makeReqHeader(REQUEST_CODE_RELOGIN, 255);

	char* payload = new char[req_head_info.payload_size];
	memset(payload, 0, req_head_info.payload_size);
	memcpy(payload, client_name.c_str(), client_name.length());

	Request request;
	request.head_info = req_head_info;
	request.payload = payload;
	sendRequest(request);

	delete[] payload;
	return true;
}


bool Client::sendRegisterMessage()
{
	cout << "==> registering..." << endl;	
	ReqHead req_head_info = makeReqHeader(REQUEST_CODE_REGISTER, 255);
	char* payload = new char[req_head_info.payload_size];
	memset(payload, 0, req_head_info.payload_size);
	memcpy(payload, client_name.c_str(), client_name.length());

	Request request;
	request.head_info = req_head_info;
	request.payload = payload;
	sendRequest(request);

	delete[] payload;
	return true;
}

bool Client::sendFile()
{
	Request request;
	cout << "==> sending file..." << endl;
	ifstream infile(sendfile_name, ios::out | ios::binary);

	//--- read file content ------
	infile.seekg(0, ios::end);
	// getting file size
	size_t length = infile.tellg();
	infile.seekg(0, ios::beg);
	char* buffer = new char[length + 1];
	memset(buffer, 0, length + 1);
	infile.read(buffer, length);

	string encBuffer = this->encryptTextByAES(buffer, length, AES_key);
	uint32_t encBufferSize = encBuffer.size();
	ReqHead req_head_info = makeReqHeader(REQUEST_CODE_SEND_FILE, 4 + 255 + encBufferSize);
	request.head_info = req_head_info;
	char* payload = new char[req_head_info.payload_size];
	memset(payload, 0, req_head_info.payload_size);
	memcpy(payload, &length, 4);
	memcpy(&payload[4], sendfile_name.c_str(), sendfile_name.size());
	memcpy(&payload[259], encBuffer.c_str(), encBufferSize);

	request.payload = payload;
	sendRequest(request);

	delete[] payload;
	return true;
}

bool Client::sendCRC(bool crc_status, int ret_cnt)
{
	ReqHead req_head_info;
	memcpy(req_head_info.client_id, client_id.c_str(), 16);
	req_head_info.client_version = CLIENT_VERSION;
	if (crc_status) {
		cout << "==> crc mathced, send back confirm message to server..." << endl;
		req_head_info.code = REQUEST_CODE_CRC_OK;
	}
	else {
		if (ret_cnt < MAX_RETRY_COUNT) {
			cout << "==> crc mismatched, retry sending file..." << endl;
			req_head_info.code = REQUEST_CODE_CRC_MISMATCHED;
		}
		else {
			cout << "==> last crc matching tries, sending aborting message..." << endl;
			req_head_info.code = REQUEST_CODE_LAST_CRC_TRY;
		}
	}
	req_head_info.payload_size = 255;

	char* payload = new char[req_head_info.payload_size];
	memset(payload, 0, req_head_info.payload_size);
	memcpy(payload, sendfile_name.c_str(), sendfile_name.length());

	Request request;
	request.head_info = req_head_info;
	request.payload = payload;
	sendRequest(request);

	delete[] payload;
	return true;
}

bool Client::sendPublicKey()
{
	ReqHead req_head_info = makeReqHeader(REQUEST_CODE_SEND_PUBKEY, 255 + this->public_key.length());

	// Create payload containing User name and public key
	char* payload = new char[req_head_info.payload_size + 1];
	memset(payload, 0, req_head_info.payload_size + 1);
	memcpy(payload, client_name.c_str(), client_name.length());
	memcpy(&payload[255], this->public_key.c_str(), this->public_key.length());

	// send Request to server
	Request request;
	request.head_info = req_head_info;
	request.payload = payload;
	sendRequest(request);
	cout << "==> sent public key to server" << endl;
	delete[] payload;
	return true;
}

char* Client::receivePayload(RespHead& respond)
{
	recv(client_socket, (char*)&respond, sizeof(RespHead), 0);
	if (respond.payload_size == 0)
		return NULL;
	char* payload = new char[respond.payload_size + 1];
	memset(payload, 0, respond.payload_size + 1);
	recv(client_socket, payload, respond.payload_size, 0);
	return payload;
}


bool Client::recevieRegisterResponse()
{
	RespHead resp_header;
	// receive response header and payload
	char* payload = receivePayload(resp_header);	

	if (payload != NULL && resp_header.code == RESPONSE_CODE_REGISTER_SUCCESS) {
		// parse registered my id
		client_id = string(payload);

		// create file containing Client Detail
		ofstream myinfo_file(FILE_CLIENT_INFO);
		myinfo_file << client_name << endl;
		myinfo_file << client_id << endl;
		myinfo_file << private_key << endl;
		myinfo_file.close();

		delete[] payload;

		cout << "==> client registered." << endl;
		
		return true;
	}
	else {
		cout << "==> already exist this client" << endl;

		if (payload != NULL)
			delete[] payload;
		return false;
	}
}



bool Client::receiveAESkey()
{
	char* payload = NULL;
	RespHead respond;
	payload = receivePayload(respond);

	if (payload != NULL && respond.code == RESPONSE_CODE_SENDING_ENCKEY) {
		// parse payload get private key from it
		client_id = string(payload).substr(0, 16);
		AES_key = decryptTextByRSA(&payload[16], private_key);

		delete[] payload;
		cout << "==> AES key received from server" << endl;

		return true;
	}
	else {
		cout << "==> error in getting aes key from server" << endl;

		if (payload != NULL)
			delete[] payload;
		return false;
	}
}



bool Client::receiveReloginResponse()
{
	char* payload = NULL;
	RespHead respond;
	payload = receivePayload(respond);

	if (payload != NULL && respond.code == RESPONSE_CODE_RELOGIN_CONFIRMED) {
		// Extract info from payload
		client_id = string(payload).substr(0, 16);
		// get Private key for AES
		AES_key = decryptTextByRSA(&payload[16], private_key);
		delete[] payload;

		cout << "==> relogin success" << endl;

		return true;
	}
	else {
		if (payload != NULL)
			delete[] payload;

		cout << "==> error in relogin" << endl;

		return false;
	}
}

bool Client::receiveFileAcceptedResponse()
{
	char* payload = NULL;
	RespHead respond;
	payload = receivePayload(respond);
	cout << "==> receiving CRC from server" << endl;
	if (payload != NULL && respond.code == RESPONSE_CODE_FILE_UPLOADED) {
		// extract infomation from Payload
		client_id = string(payload).substr(0, 16);
		int contents_size;
		memcpy(&contents_size, &payload[16], 4);
		
		// CRC information
		string file_name = string(&payload[20]).substr(0, 255);
		uint32_t crc;
		memcpy(&crc, &payload[275], 4);
		stringstream stream;
		stream << hex << crc;
		string crcReceived(stream.str());

		// caclualte crc code from file name
		string crc_origin = getCRC32(file_name);
		delete[] payload;

		if (crcReceived != crc_origin) {
			cout << "==> CRC mismatched, retry to send file" << endl;
			return false;
		}
		else {
			cout << "==> CRC matched" << endl;
			return true;
		}		
	}
	else {
		if (payload != NULL)
			delete[] payload;
		return false;
	}
}



bool Client::receiveConfirmMessage(int retries)
{
	char* payload = NULL;
	RespHead respond;
	payload = receivePayload(respond);

	if (payload != NULL && respond.code == RESPONSE_CODE_MESSAGE_CONFIRMED) {
		// parse payload
		client_id = string(payload).substr(0, 16);
		if (retries > MAX_RETRY_COUNT) {
			cout << "==> abort file transfer.\n" << endl;
		}
		else {
			cout << "==> file transfered successfully.\n" << endl;
		}
		return true;
	}
	else {
		if (payload != NULL)
			delete[] payload;
		cout << "==> internal server error" << endl;
		return false;
	}
}

void Client::InitializeKeys()
{
	string der_private;
	string der_public;

	// create private key
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey_func;
	privkey_func.Initialize(rng, 1024);	
	Base64Encoder privkeystr_sink(new StringSink(der_private));
	privkey_func.DEREncode(privkeystr_sink);
	privkeystr_sink.MessageEnd();	
	private_key = der_private;

	// Create Public Key	
	RSAFunction pubkey_func(privkey_func);
	Base64Encoder pubkeystr_sink(new StringSink(der_public));
	pubkey_func.DEREncode(pubkeystr_sink);
	pubkeystr_sink.MessageEnd();
	public_key = der_public;

	
	public_key.erase(std::remove_if(public_key.begin(), public_key.end(),
		[](char c) { return c == '\n'; }),
		public_key.end());

	
	private_key.erase(std::remove_if(private_key.begin(), private_key.end(),
		[](char c) { return c == '\n'; }),
		private_key.end());
}

string Client::decryptTextByRSA(char* cipher_text, string private_key)
{
	ByteQueue bytes;
	StringSource ss_privkey(private_key, true, new Base64Decoder);
	ss_privkey.TransferTo(bytes);
	bytes.MessageEnd();

	RSA::PrivateKey privateKey;
	privateKey.Load(bytes);

	string b64_cipher;
	StringSource ss_ciphertext(cipher_text, true, new Base64Decoder(new StringSink(b64_cipher)));

	string plain_text;
	RSAES_PKCS1v15_Decryptor decryptor(privateKey);
	AutoSeededRandomPool rnd_pool;
	StringSink* ssink_plaintext = new StringSink(plain_text);
	PK_DecryptorFilter* dcrypt_filter = new PK_DecryptorFilter(rnd_pool, decryptor, ssink_plaintext);
	StringSource ss2(b64_cipher, true, dcrypt_filter);

	return plain_text;
}

string Client::encryptTextByAES(char* plain_text, size_t plain_length, string aes_key_b64encoded)
{
	string b64_cipher;
	// get aes key
	byte key[AES::MIN_KEYLENGTH];
	byte iv[AES::BLOCKSIZE];
	vector<byte> plain_vect, cipher;
	plain_vect.assign(plain_text, plain_text + plain_length);

	string aes_key;
	StringSink* ssink_aeskey = new StringSink(aes_key);
	StringSource ss1(aes_key_b64encoded, true, new Base64Decoder(ssink_aeskey));

	memset(key, 0x00, sizeof(key));
	memcpy(key, aes_key.c_str(), aes_key.length());
	memset(iv, 0x00, sizeof(iv));

	CBC_Mode<AES>::Encryption enc;
	enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	// make room for padding
	cipher.resize(plain_length + AES::BLOCKSIZE);
	ArraySink arr_sink_cipher(&cipher[0], cipher.size());
	Redirector* redir = new Redirector(arr_sink_cipher);
	StreamTransformationFilter* stf_filter = new StreamTransformationFilter(enc, redir);
	ArraySource(plain_vect.data(), plain_vect.size(), true, (BufferedTransformation*)stf_filter);

	// assign length of cipher text
	cipher.resize(arr_sink_cipher.TotalPutLength());
	string cipherString(cipher.begin(), cipher.end());	

	// convert to base64 format string
	StringSink* ssink_b64cipher = new StringSink(b64_cipher);
	StringSource ss(cipherString, true, new Base64Encoder(ssink_b64cipher));

	return b64_cipher;
}

string Client::getCRC32(string file_name)
{
	CRC32 hash;
	string result;

	FileSource fs(file_name.c_str(), true,
		new HashFilter(hash,
			new HexEncoder(
				new StringSink(result))));

	return result;
}


bool Client::initializeClient()
{
	bool init_ok = false;
	this->InitializeKeys();
	this->loadClientInfo(FILE_CLIENT_INFO);
	// load transfer infomation
	if (this->loadTransferInfo(FILE_TRANSFER_INFO)) {
		// connect to server
		if (this->connectToServer()) {
			init_ok = true;
		}
	}
	return init_ok;
}

void Client::processUploadingTask()
{	
	bool login_ok = false;
	bool sent_ok = false;
	if (register_status) {
		if (sendReloginRequest()) {
			if (receiveReloginResponse()){
				if (loadClientInfo(FILE_CLIENT_INFO)) {
					login_ok = true;
				}
			}
				
		}		
	}
	else {
		if (sendRegisterMessage()) {
			if (recevieRegisterResponse()) {
				if (loadClientInfo(FILE_CLIENT_INFO)) {
					if (sendPublicKey()) {
						if (receiveAESkey())
							login_ok = true;
					}
				}
			}
			
		}		
	}
	if (login_ok) {		
		for (int n_tries = 0; n_tries <= MAX_RETRY_COUNT; n_tries++) {
			if (sendFile()) {
				if (receiveFileAcceptedResponse()) {
					sent_ok = true;
					break;
				}
				else {
					if (sendCRC(true, n_tries)) {
						if (receiveConfirmMessage(n_tries))
							break;
					}
				}
			}
		}
	}
	
}


