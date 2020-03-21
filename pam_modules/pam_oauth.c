#define PAM_SM_AUTH

#include <security/pam_modules.h> 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

//#define ACTIVE_DEBUG

#ifdef ACTIVE_DEBUG
#define LOG_FUNC(msg, ...) syslog(LOG_INFO, msg, ##__VA_ARGS__) 
#else
#define LOG_FUNC(msg, ...) NULL
#endif

typedef struct pam_conv pam_conv;
typedef struct pam_response pam_response;
typedef struct pam_message pam_message;

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flag, int argc, const char** argv)
{
	const char* username = NULL;
   	char* password = NULL;
	FILE* configFile = NULL;
	char* line = NULL, *name = NULL, *pass = NULL;
	char* retval = NULL; 
	int authenticated = PAM_AUTH_ERR;
	pam_conv* passConv;
	pam_message* msg = NULL;
	pam_response* resp = NULL;

	openlog("pamlog2", LOG_CONS, LOG_USER);
	LOG_FUNC("cool beans");

	if(pam_get_user(pamh, &username, NULL) != PAM_SUCCESS)
	{
		LOG_FUNC("couldn't get username");
		closelog();
		return PAM_AUTH_ERR;
	}

	if(pam_get_item(pamh, PAM_CONV, (const void**)&passConv) != PAM_SUCCESS)
	{
		LOG_FUNC("couldn't get password conv");
		closelog();
		return PAM_AUTH_ERR;
	}

	msg = (pam_message*)malloc(sizeof(pam_message));
	if(msg == NULL)
	{
		LOG_FUNC("bad allocation :(");
		closelog();
		return PAM_AUTH_ERR;
	}

	msg->msg_style = PAM_PROMPT_ECHO_OFF;
	msg->msg = NULL;
	if(passConv->conv(1, (const pam_message**)&msg, &resp, NULL) != PAM_SUCCESS)
	{
		free(msg);
		LOG_FUNC("couldn't password");
		closelog();
		return PAM_AUTH_ERR;
	}
	
	if(resp->resp_retcode != PAM_SUCCESS)
	{
		free(msg);
		free(resp->resp);
		free(resp);
		LOG_FUNC("convo func failed");
		closelog();
		return PAM_AUTH_ERR;
	}

	if((password = strdup(resp->resp)) == NULL)
	{
		free(msg);
		free(resp->resp);
		free(resp);
		LOG_FUNC("bad alloc :(");
		closelog();
		return PAM_AUTH_ERR;
	}

	free(msg);
	free(resp->resp);
	free(resp);

	LOG_FUNC("username: %s", username);
	LOG_FUNC("password: %s", password);

	if((configFile = fopen("/etc/pasten.conf", "r")) == NULL)
	{
		free(password);
		LOG_FUNC("couldn't open config file");
		closelog();
		return PAM_AUTH_ERR;
	}

	line = (char*)malloc(200);

	if(line == NULL)
	{
		free(password);
		fclose(configFile);
		LOG_FUNC("bad allocation :(");
		closelog();
		return PAM_AUTH_ERR;
	}

	LOG_FUNC("successful setup");

	retval = fgets(line, 200, configFile);
	while(retval == line)
	{
		if(line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = 0;
		
		pass = strchr(line, '=');
		if(pass != NULL)
		{
			*pass = 0;
			pass++;
			name = line;
			LOG_FUNC("name: %s, pass: %s", name, pass);

			if(strcmp(name, username) == 0 && strcmp(pass, password) == 0)
			{
				authenticated = PAM_SUCCESS;
				break;
			}
		}
		retval = fgets(line, 200, configFile);
	}

	free(password);
	free(line);
	fclose(configFile);

	LOG_FUNC("exiting cleanly");
	closelog();

	return authenticated;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flag, int argc, const char** argv)
{
	return PAM_SUCCESS;
}
