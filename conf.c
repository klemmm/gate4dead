 
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <assert.h>

#include "conf.h"


static char *conf_keywords[] = {
  "BANLIST_FILE",
  "ROOM_HOST",
  "ROOM_ID",
  "USERNAME",
  "PASSWORD",
  "SERVER",
  "LPORT",
  "L4DSERV_HOST",
  "L4DSERV_PORT",
  "BIND_HOST", 
  "SYMMETRIC"
};

confkey_t conf_mandatory[] = {
  CONF_ROOM_HOST,
  CONF_ROOM_ID,
  CONF_USERNAME,
  CONF_PASSWORD,
  CONF_SERVER,
  CONF_L4DSERV_HOST,
  CONF_MAX
};

static char *conf_base[CONF_MAX];

static confkey_t keyword2key(char *keyword) {
  int i;
  for (i = 0; (i < CONF_MAX) && strcasecmp(keyword, conf_keywords[i]); i++);
  return i;
}

void conf_free() {
  int i;
  for (i = 0; i < CONF_MAX; i++) {
    free(conf_base[i]);
    conf_base[i] = 0;
  }
}

void conf_load(char *filename) {
  FILE *f;
  char buf[CONFLINESIZE];
  char *ptr;
  int i;
  int line = 0;
  confkey_t key;
  char *keyword, *endk;
  char *value, *endv;
  
  f = fopen(filename, "r");
  if (f == NULL) {
    perror("opening config file");
    exit(-1);
  }
  
  while (fgets(buf, CONFLINESIZE, f) != NULL) {
    buf[CONFLINESIZE-1] = 0;
    line++;

    /* remove comments */
    ptr = strchr(buf, '#');
    if (ptr != NULL)
      *ptr = '\0';
    ptr = buf;
    
    
    /* skip leading spaces */
    for (;isspace(*ptr) && (*ptr != '\0'); ptr++);
    if (*ptr == '\0')
      continue;
          
    
    /* fetch keyword */
    keyword = ptr; 
    for (;!isspace(*ptr) && (*ptr != '\0'); ptr++);
    endk = ptr;
    
    /* skip spaces between keyword and value */
    for (;isspace(*ptr) && (*ptr != '\0'); ptr++);
    if (*ptr == '\0') {
      fprintf(stderr, "Missing value at line %u\n", line);
      exit(-1);
    }
    
    /* fetch value */
    value = ptr;
    for (;!isspace(*ptr) && (*ptr != '\0'); ptr++);
    endv = ptr;
    
    for (; *ptr != '\0'; ptr++) {
      if (!isspace(*ptr)) {
        fprintf(stderr, "Unexpected text at end of line %u\n", line);
        exit(-1);
      }
    }
    
    *endk = '\0';
    *endv = '\0';
    
    
    key = keyword2key(keyword);
    if (key == CONF_UNKNOWN) {    
      fprintf(stderr, "Unknown keyword %s on line %u\n", keyword, line);
      exit(-1);
    }
    conf_base[key] = malloc(strlen(value) + 1);
    assert(conf_base[key] != NULL);
    strcpy(conf_base[key], value);
  }
  fclose(f);
  for (i = 0; conf_mandatory[i] != CONF_MAX; i++) {
    if (conf_base[conf_mandatory[i]] == NULL) {
      fprintf(stderr, "Mandatory configuration key %s not found.\n",
      conf_keywords[conf_mandatory[i]]);
      exit(-1);
    }
  }  
}

const char *conf_getval(confkey_t key) {
  return conf_base[key];
}
