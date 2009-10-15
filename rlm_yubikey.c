/*
 * rlm_yubikey.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2009  Danila Dumitrescu Mircea <venatir@xss.ro>
 */

#include <freeradius-devel/ident.h>

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "yubikey.h"
#include "libconfig.h"
#include "md5.h"


#define KEYS_PATH "main.aeskeys.key_"
#define USERS_PATH "main.users"


/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_yubikey_t
{
    int boolean;
    int value;
    char *string;
    uint32_t ipaddr;
} rlm_yubikey_t;

typedef struct _myConf
{
    struct config_t config;
    config_setting_t *config_setting;
    char *md5ComputedString;
    char *token;
    char *pass;

} myConf_t;



/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
    { "integer", PW_TYPE_INTEGER, offsetof(rlm_yubikey_t, value), NULL, "1"},
    { "boolean", PW_TYPE_BOOLEAN, offsetof(rlm_yubikey_t, boolean), NULL, "no"},
    { "string", PW_TYPE_STRING_PTR, offsetof(rlm_yubikey_t, string), NULL, NULL},
    { "ipaddr", PW_TYPE_IPADDR, offsetof(rlm_yubikey_t, ipaddr), NULL, "*"},

    { NULL, -1, 0, NULL, NULL} /* end the list */
};

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int yubikey_instantiate(CONF_SECTION *conf, void **instance)
{
    rlm_yubikey_t *data;

    /*
     *	Set up a storage area for instance data
     */
    data = rad_malloc(sizeof (*data));
    if (!data)
    {
        return -1;
    }
    memset(data, 0, sizeof (*data));

    /*
     *	If the configuration parameters can't be parsed, then
     *	fail.
     */
    if (cf_section_parse(conf, data, module_config) < 0)
    {
        free(data);
        return -1;
    }

    *instance = data;

    return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int yubikey_authorize(void *instance, REQUEST *request)
{
    //	VALUE_PAIR *state;
    //	VALUE_PAIR *reply;

    if (pairfind(request->config_items, PW_AUTHTYPE) != NULL)
    {
        RDEBUG2("WARNING: Auth-Type already set.  Not setting to YUBIKEY");
        return RLM_MODULE_NOOP;
    }

    RDEBUG("Setting 'Auth-Type := YUBIKEY'");
    pairadd(&request->config_items,
            pairmake("Auth-Type", "YUBIKEY", T_OP_EQ));
    return RLM_MODULE_OK;


    /* quiet the compiler */
    instance = instance;
    request = request;
    DEBUG("rlm_yubikey: Authorizing user %s", request->username->vp_strvalue);
    return RLM_MODULE_OK;
    /*
     *  Look for the 'state' attribute.
     */
    /*	state =  pairfind(request->packet->vps, PW_STATE);
            if (state != NULL) {
                    RDEBUG("Found reply to access challenge");
                    return RLM_MODULE_OK;
            }
     */
    /*
     *  Create the challenge, and add it to the reply.
     */
    /*     	reply = pairmake("Reply-Message", "This is a challenge", T_OP_EQ);
            pairadd(&request->reply->vps, reply);
            state = pairmake("State", "0", T_OP_EQ);
            pairadd(&request->reply->vps, state);
     */
    /*
     *  Mark the packet as an Access-Challenge packet.
     *
     *  The server will take care of sending it to the user.
     */
    /*	request->reply->code = PW_ACCESS_CHALLENGE;
            RDEBUG("Sending Access-Challenge.");
            return RLM_MODULE_OK;
     */
}

static int yubikey_auth_core(myConf_t *myConf, REQUEST *request)
{
    int passLen = 0, session = 0, counter = 0, i = 0;
    MD5_CTX ctx;
    int result = 0;
    char *filename = "/usr/local/etc/raddb/yubico/users";

    //get password by removing the last 32 characters of the password
    if (strlen(request->password->vp_strvalue) <= 32)
    {
        DEBUG("rlm_yubikey: Password too short.");
        return RLM_MODULE_REJECT;
    }

    passLen = strlen(request->password->vp_strvalue) - 32;
    strncpy(myConf->pass, request->password->vp_strvalue, passLen);
    myConf->pass[passLen] = '\0';
    strncpy(myConf->token, request->password->vp_strvalue + passLen, 32);
    myConf->token[32] = '\0';

    //md5 stuff
    MD5Init(&ctx);
    DEBUG("rlm_yubikey: length: %d, string: %s", passLen, myConf->pass);
    MD5Update(&ctx, (unsigned char *)myConf->pass, passLen);
    MD5Final(&ctx);
    MD5toString(&ctx, myConf->md5ComputedString);
    myConf->md5ComputedString[32] = '\0';
    DEBUG("rlm_yubikey: MD5string of your pass: %s", myConf->md5ComputedString);
    DEBUG("rlm_yubikey: Username: %s", request->username->vp_strvalue);

    //read file
    result = config_read_file(&(myConf->config), filename);
    if (result != CONFIG_TRUE)
    {
        DEBUG("rlm_yubikey: Failed to parse configuration file: config_read_file (&config, filename);");
        DEBUG("config_error_text()= %s and config_error_line()=%d", config_error_text(&(myConf->config)), config_error_line(&(myConf->config)));
        return RLM_MODULE_FAIL;
    }

    //parse file
    myConf->config_setting = config_lookup(&(myConf->config), USERS_PATH);
    if (myConf->config_setting == NULL)
    {
        DEBUG("rlm_yubikey: Failed to parse configuration file: config_lookup failed to find the users node");
        return RLM_MODULE_FAIL;
    }

    //go through the list of users
    for (i = 0; i < config_setting_length(myConf->config_setting); i++)
    {
        DEBUG("Trying i: %d", i);
        config_setting_t *tmpSetting = NULL;
        tmpSetting = config_setting_get_elem(myConf->config_setting, i);
        if (tmpSetting == NULL)
        {
            DEBUG("rlm_yubikey: Failed to parse configuration file: config_setting_get_elem(config_setting,i);");
            return RLM_MODULE_FAIL;
        }

        if ((config_setting_get_string_elem(myConf->config_setting, 0) == NULL) ||
                (config_setting_get_string_elem(myConf->config_setting, 1) == NULL) ||
                (config_setting_get_string_elem(myConf->config_setting, 2) == NULL))
        {
            DEBUG("rlm_yubikey: Failed to parse configuration file: if ((config_setting_get_string_elem(config_setting,0)==NULL)||(config_setting_get_string_elem(config_setting,1)==NULL)||(config_setting_get_string_elem(config_setting,2)==NULL)) ");
            return RLM_MODULE_FAIL;
        }

        //check usernames are equal
        if (strcmp(request->username->vp_strvalue, config_setting_get_string_elem(myConf->config_setting, 0)) != 0)
        {
            //users do not match. No need to debug this
            //Go to next iteration
            continue;
        }

        //check passwords are equal
        if (strcmp(myConf->md5ComputedString, config_setting_get_string_elem(myConf->config_setting, 1)) != 0)
        {
            //passwords do not match. We debug
            DEBUG("rlm_yubikey: Password does not match for user %s", request->username->vp_strvalue);
            //Go to next iteration
            continue;
        }

        //check aes stuff - mostly copied from the ykdebug.c that comes with the low-level yubikey library
        uint8_t buf[128];
        const char *aeskey = config_setting_get_string_elem(myConf->config_setting, 2);
        char *token = myConf->token;
        uint8_t key[YUBIKEY_KEY_SIZE];
        yubikey_token_st tok;

        yubikey_modhex_decode((char*) key, token, YUBIKEY_KEY_SIZE);
        DEBUG("rlm_yubikey:  aeskey: %s", aeskey);

        yubikey_hex_decode((char*) key, aeskey, YUBIKEY_KEY_SIZE);

        /* Pack up dynamic password, decrypt it and verify checksum */
        yubikey_parse((uint8_t*) token, key, &tok);

        DEBUG("rlm_yubikey: Struct:");
        size_t i;
        char *tmp = (char*) malloc(1024);
        for (i = 0; i < YUBIKEY_UID_SIZE; i++)
        {
            sprintf(tmp + i, "%c ", tok.uid[i] & 0xFF);
        }
        tmp[YUBIKEY_UID_SIZE + i] = 0;
        DEBUG("rlm_yubikey:   uid:%s", tmp);
        free(tmp);

        DEBUG("rlm_yubikey:   counter: %d (0x%04x)", tok.ctr, tok.ctr);
        DEBUG("rlm_yubikey:   timestamp (low): %d (0x%04x)", tok.tstpl, tok.tstpl);
        DEBUG("rlm_yubikey:   timestamp (high): %d (0x%02x)", tok.tstph, tok.tstph);
        DEBUG("rlm_yubikey:   session use: %d (0x%02x)", tok.use, tok.use);
        DEBUG("rlm_yubikey:   random: %d (0x%02x)", tok.rnd, tok.rnd);
        DEBUG("rlm_yubikey:   crc: %d (0x%04x)", tok.crc, tok.crc);
        DEBUG("rlm_yubikey: Derived:");
        DEBUG("rlm_yubikey:   cleaned counter: %d (0x%04x)",yubikey_counter(tok.ctr), yubikey_counter(tok.ctr));

        yubikey_modhex_encode((char*) buf, (char*) tok.uid, YUBIKEY_UID_SIZE);

        DEBUG("rlm_yubikey:   modhex uid: %s", buf);
        DEBUG("rlm_yubikey:   triggered by caps lock: %s", yubikey_capslock(tok.ctr) ? "yes" : "no");
        DEBUG("rlm_yubikey:   crc: %04X", yubikey_crc16((void*) & tok, YUBIKEY_KEY_SIZE));
        DEBUG("rlm_yubikey:   crc check: ");
        if (yubikey_crc_ok_p((uint8_t*) & tok))
        {
            DEBUG("rlm_yubikey:   ok");

            char *tmppath = KEYS_PATH;
            char *path = (char*) malloc(strlen(tmppath) + 32 + 1);
            strcpy(path, tmppath);
            strcat(path, aeskey);


            myConf->config_setting = config_lookup(&(myConf->config), path);
            if (myConf->config_setting == NULL)
            {
                DEBUG("rlm_yubikey: Error parsing file: %s not found", path);
                return RLM_MODULE_FAIL;
            }

            //checking counter and session and update them if necessary
            counter = config_setting_get_int_elem(myConf->config_setting, 0);
            session = config_setting_get_int_elem(myConf->config_setting, 1);
            DEBUG("rlm_yubikey: Read counter: %d, session: %d", counter, session);

            if ((tok.ctr < counter)||((tok.ctr == counter) && (session <= tok.use)))
            {
                DEBUG("rlm_yubikey: someone tried to login with an old generated hash");
                return RLM_MODULE_REJECT;
            }

            //updating config file with counter and session
            config_setting_set_int_elem(myConf->config_setting, 0, tok.ctr);
            config_setting_set_int_elem(myConf->config_setting, 1, tok.use);


            DEBUG("rlm_yubikey: Written element: %ld", config_setting_get_int_elem(myConf->config_setting, 0));
            DEBUG("rlm_yubikey: Written element: %ld", config_setting_get_int_elem(myConf->config_setting, 1));
            if (CONFIG_FALSE == config_write_file(&(myConf->config), filename))
            {
                DEBUG("rlm_yubikey: Failed to write the file.");
                return RLM_MODULE_FAIL;
            }

            return RLM_MODULE_OK;
        }
        DEBUG("rlm_yubikey:   fail");
    }
    DEBUG("rlm_yubikey: Authenticating with password %s", request->password->vp_strvalue);
    return RLM_MODULE_REJECT;
}

static void init(myConf_t *myConf, REQUEST *request)
{
    memset(myConf, 0, sizeof (myConf_t));
    config_init(&(myConf->config));
    myConf->md5ComputedString = (char*) malloc(32);
    myConf->token = (char*) malloc(32);
    myConf->pass = (char*) malloc(strlen(request->password->vp_strvalue) - 32 + 1);
}

static void clean(myConf_t *myConf)
{
    free(myConf->pass);
    free(myConf->token);
    free(myConf->md5ComputedString);
    config_destroy(&(myConf->config));
}

/*
 *	Authenticate the user with the given password.
 */
static int yubikey_authenticate(void *instance, REQUEST *request)
{

    int result = 0;
    myConf_t myConf;
    /* quiet the compiler */
    instance = instance;
    request = request;

    init(&myConf,request);
    result = yubikey_auth_core(&myConf, request);
    clean(&myConf);
    return result;
}

/*
 *	Massage the request before recording it or proxying it
 */
static int yubikey_preacct(void *instance, REQUEST *request)
{
    /* quiet the compiler */
    instance = instance;
    request = request;

    return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static int yubikey_accounting(void *instance, REQUEST *request)
{
    /* quiet the compiler */
    instance = instance;
    request = request;

    return RLM_MODULE_OK;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int yubikey_detach(void *instance)
{
    free(instance);
    return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_yubikey = {
    RLM_MODULE_INIT,
    "yubikey",
    RLM_TYPE_THREAD_UNSAFE, /* type */
    yubikey_instantiate, /* instantiation */
    yubikey_detach, /* detach */
    {
        yubikey_authenticate, /* authentication */
        yubikey_authorize, /* authorization */
        NULL, /* preaccounting */
        NULL, /* accounting */
        NULL, /* checksimul */
        NULL, /* pre-proxy */
        NULL, /* post-proxy */
        NULL /* post-auth */
    },
};
