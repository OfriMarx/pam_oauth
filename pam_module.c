#define PAM_SM_AUTH
//#define PAM_SM_ACCOUNT

#include <security/pam_modules.h> 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

//#define LOL_DEBUG

#ifdef LOL_DEBUG
#define LOG_FUNC(msg, ...) syslog(LOG_INFO, msg, ##__VA_ARGS__) 
#else
#define LOG_FUNC(msg, ...) NULL
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flag, int argc, const char** argv)
{
	const char* username = NULL;
	FILE* configFile = NULL;
	char* line = NULL, *name = NULL, *pass = NULL;
	char* retval = NULL; 
	int authenticated = PAM_AUTH_ERR;

	openlog("pamlog2", LOG_CONS, LOG_USER);
	LOG_FUNC("cool beans");

	if(pam_get_user(pamh, &username, "pass for totaly secure system: ") != PAM_SUCCESS)
	{
		LOG_FUNC("couldn't get username");
		closelog();
		return PAM_AUTH_ERR;
	}

	if((configFile = fopen("/etc/pasten.conf", "r")) == NULL)
	{
		LOG_FUNC("couldn't open config file");
		closelog();
		return PAM_AUTH_ERR;
	}

	line = (char*)malloc(200);

	if(line == NULL)
	{
		fclose(configFile);
		LOG_FUNC("bad allocation :(");
		closelog();
		return PAM_AUTH_ERR;
	}

	LOG_FUNC("successfull setup");

	retval = fgets(line, 200, configFile);
	while(retval == line)
	{
		if(line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = 0;
		LOG_FUNC("line: %s", line);
		
		pass = strchr(line, '=');
		if(pass != NULL)
		{
			*pass = 0;
			pass++;
			name = line;
			LOG_FUNC("name: %s, pass: %s", name, pass);

			if(strcmp(name, username) == 0)
			{
				authenticated = PAM_SUCCESS;
				break;
			}
		}
		retval = fgets(line, 200, configFile);
	}

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

//PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flag, int argc, const char** argv)
//{
//	return PAM_SUCCESS;
//}
