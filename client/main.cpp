#include "Client.h"

void main()
{
	Client client = Client();	
	if (client.initializeClient()) {
		client.processUploadingTask();
	}	
	return;
}