/*
 * Header for access to configuration data
 */
#ifndef TM_CONF_H
#define TM_CONF_H 1

#define CONFLINESIZE 512

typedef enum {
  CONF_BANLIST_FILE = 0,
  CONF_ROOM_HOST = 1,
  CONF_ROOM_ID = 2,
  CONF_USERNAME = 3,
  CONF_PASSWORD = 4,
  CONF_SERVER = 5,
  CONF_LPORT = 6,
  CONF_L4DSERV_HOST = 7,
  CONF_L4DSERV_PORT = 8,
  CONF_BIND_HOST = 9,
  CONF_SYMMETRIC = 10,
  CONF_L4D_VERSION = 11,
  CONF_MAX = 12
} confkey_t;
#define CONF_UNKNOWN CONF_MAX

const char *conf_getval(confkey_t key);
void conf_load();
void conf_free();

#endif
