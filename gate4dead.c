#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <garena/garena.h>
#include <garena/ghl.h>
#include <garena/error.h>

#include "conf.h"

struct gateinfo_s {
  unsigned int room_ip;
  int room_id;
  ghl_serv_t *serv;
};


int quit = 0;
int ready = 0;


typedef int cmdfun_t(struct gateinfo_s *gateinfo, int parc, char **parv);
typedef struct {
  cmdfun_t *fun;
  char *str;
} cmd_t;

#define MAX_CMDS 4
#define MAX_PARAMS 16
cmd_t cmdtab[];

int handle_cmd_help(struct gateinfo_s *gateinfo, int parc, char **parv) {
  int i;
  printf("Available commands:");
  for (i = 0; i < MAX_CMDS; i++)
    printf(" %s", cmdtab[i].str);
  printf("\n");
  return 0;
}


int handle_cmd_who(struct gateinfo_s *gateinfo, int parc, char **parv) {
    ghl_room_t *rh = gateinfo->serv ? gateinfo->serv->room : NULL;
    int total = 0;
    ihashitem_t iter;
    ghl_member_t *member;
    int boldness, color;
    struct winsize ws;
    int pos;
    ioctl(0, TIOCGWINSZ, &ws);
          
    if (!rh || !rh->joined) {
      printf( "You are not in a room\n");
      return - 1;
    }
    printf( "\x1B[36;1m --------=========[Room members]=========-------- \x1B[37;22m\n");
    pos = 0;
    for (iter = ihash_iter(rh->members); iter; iter = ihash_next(rh->members, iter)) {
      member = ihash_val(iter);
        if (pos + 20 >= ws.ws_col) {
          printf("\n");
          pos = 0;
        }
        if (member->conn_ok != 2) {
          boldness = 22;
          color = 37;
        } else {
          boldness = 1;
          color = member->vpn ? 31 : 32;
        }
        if (member->user_id == gateinfo->serv->my_info.user_id) {
          boldness = 1;
          color = 34;
        }
        printf("\x1B[33;1m[\x1B[%u;%um%16s\x1B[33;1m]\x1B[37;22m ", color, boldness, member->name);
        pos += 19;
        total++;
      }
    printf( "\n\x1B[36;1m -----\x1B[33;1m[\x1B[31;1mPLAYING\x1B[33;1m]\x1B[37;22m \x1B[33;1m[\x1B[32;1mNOT PLAYING\x1B[33;1m]\x1B[37;22m \x1B[33;1m[\x1B[37;22mUNREACHABLE\x1B[33;1m]\x1B[36;1m------ \x1B[37;22m\n");
    return 0;


}

int handle_cmd_whois(struct gateinfo_s *gateinfo, int parc, char **parv) {
  ghl_room_t *rh = gateinfo->serv ? gateinfo->serv->room : NULL;
  ghl_member_t *member;
  ihashitem_t iter;

  int found = 0;
  
  if (parc != 2) {
    printf("Usage: /WHOIS <name|IP|ID>\n");
    return -1;
  }
  if (!rh || !rh->joined) {
      printf("You are not in a room\n");
      return - 1;
  }
  for (iter = ihash_iter(rh->members); iter; iter = ihash_next(rh->members, iter)) {
      member = ihash_val(iter);
      if  ((strcasecmp(member->name, parv[1]) == 0) ||
          (((member->virtual_suffix << 24) | inet_addr(GARENA_NETWORK)) == inet_addr(parv[1]) ) ||
          (member->external_ip.s_addr == inet_addr(parv[1])) ||
          (member->internal_ip.s_addr == inet_addr(parv[1])) ||
          (ghtonl(member->user_id) == strtoul(parv[1], NULL, 16))) {
            printf("\x1B[36;1m+--------------------------------------\n");
            printf("\x1B[36;1m|\x1B[37m Member name      : \x1B[32m%s\n", member->name);
            printf("\x1B[36;1m|\x1B[37m User ID          : \x1B[32m%u\n", member->user_id);
            printf("\x1B[36;1m|\x1B[37m Country          : \x1B[32m%s\n", member->country);
            printf("\x1B[36;1m|\x1B[37m Level            : \x1B[34m%u\n", member->level);
            printf("\x1B[36;1m|\x1B[37m In game          : \x1B[34m%s\n", member->vpn ? "yes" : "no" );
            printf("\x1B[36;1m|\x1B[37m Virtual IP       : \x1B[33m192.168.29.%u\n", member->virtual_suffix);
            printf("\x1B[36;1m|\x1B[37m External ip/port : \x1B[33m%s:%u\n", inet_ntoa(member->external_ip), member->external_port);
            printf("\x1B[36;1m|\x1B[37m Internal ip/port : \x1B[33m%s:%u\n", inet_ntoa(member->internal_ip), member->internal_port);
            if (member->conn_ok == 2) {
              printf("\x1B[36;1m|\x1B[37m Ping             : \x1B[31m%u msec\n", member->ping);
            } else printf("\x1B[36;1m|\x1B[37m Ping             : \x1B[31mN/A\n");
            printf("\x1B[36;1m+--------------------------------------\n");
            found = 1;
      }
  }
  if (!found)
    printf("User not found.\n");
  return -1;

  
}
int handle_cmd_quit(struct gateinfo_s *gateinfo, int parc, char **parv) {
  quit = 1;
  return 0;
}


cmd_t cmdtab[MAX_CMDS] = {
 {handle_cmd_help, "HELP"},
 {handle_cmd_who, "WHO"},
 {handle_cmd_whois, "WHOIS"},
 {handle_cmd_quit, "QUIT"},
};

 
void handle_command(struct gateinfo_s *gateinfo, char *buf) {
  char tmp[512];
  int i;
  int state = 0;
  int parc;
  int len = strlen(buf);
  char *parv[MAX_PARAMS];
  for (i = 0, parc = 0; i < len; i++) {
    if (state == 0) {
      if (buf[i] != ' ') {
        state = 1;
        parv[parc] = buf + i;
        parc++;
        if (parc == MAX_PARAMS)
          return;
      } else buf[i] = '\0';
    } else {
      if (buf[i] == ' ') {
        state = 0;
        buf[i] = '\0';
      }
    }
  }
  
  if (parc > 0) {
    for (i = 0 ; i < MAX_CMDS; i++) {
      if ((cmdtab[i].fun != NULL) && (strcasecmp(parv[0], cmdtab[i].str) == 0)) {
        cmdtab[i].fun(gateinfo, parc, parv);
        break;
      }
    }
    if (i == MAX_CMDS)
      printf("Unknown command: %s\n", parv[0]);
  
  }
}


int resolve(const char *addr) {
  if (inet_addr(addr) == INADDR_NONE) {
      struct hostent *he;
      fflush(stdout);
      he=gethostbyname(addr);
      if(he==NULL) {
        return INADDR_NONE;
      }
      return (*(int *)he->h_addr);
  }
  return(inet_addr(addr));
}

int handle_me_join(ghl_serv_t *serv, int event, void *event_param, void *privdata) {
  ghl_me_join_t *join = event_param;   
  struct gateinfo_s *gateinfo = privdata;
  if (join->result == GHL_EV_RES_SUCCESS) {
    printf("Room %x joined.\n", gateinfo->room_id);
    ghl_togglevpn(serv->room, 1);
    ready = 1;
    printf("\x1B[1m\x1B[37mgate4dead>\x1B[22m ");
    fflush(stdout);
  } else {
    fprintf(stderr, "Room join failed.\n");
    quit = 2;
  }
  return 0;
}

int handle_kick(ghl_serv_t *serveur, int event, void *event_param, void *privdata) {
  fprintf(stderr, "Kicked from room!\n");
  quit = 2;
  return 0;
}

int handle_servconn(ghl_serv_t *serv, int event, void *event_param, void *privdata) {
  struct gateinfo_s *gateinfo = privdata;
  ghl_room_t *room;
  ghl_servconn_t *servconn = event_param;
  if (servconn->result == GHL_EV_RES_SUCCESS) {
    printf("Connected to server, joining room (ID %x)...\n", gateinfo->room_id);

    room = ghl_join_room(serv, gateinfo->room_ip, 0, gateinfo->room_id);
    if (room == NULL) {
      garena_perror("Failed to join room");
      exit(-1);
    } else printf("Room join in progress...\n");
  } else {
    fprintf(stderr, "Connection to server failed\n");
    exit(-1);
  }
  return 0;
}


void register_handlers(ghl_serv_t *serv, struct gateinfo_s *gateinfo) {
  ghl_register_handler(serv, GHL_EV_SERVCONN, handle_servconn, gateinfo);
  ghl_register_handler(serv, GHL_EV_ROOM_DISC, handle_kick, gateinfo);
  ghl_register_handler(serv, GHL_EV_ME_JOIN, handle_me_join, gateinfo);
}

void handle_quit(int crap) {
  quit = 1;
}

int main(int argc, char **argv) {
  unsigned int server_ip, room_ip;
  struct in_addr saddr;
  int lport = 0;
  int handled = 0;
  int room_id, maxfd;
  ghl_serv_t *serv;
  struct gateinfo_s gateinfo;
  fd_set fds;
  struct timeval tv;
  int r;
  char buf[512];
  
  if (argc != 2) {
    printf("usage: %s <config file>\n", argv[0]);
    exit(-1);
  }
  
  if (!isatty(0)) {
    printf("Standard input must be a tty.\n");
    exit(-1);
  }
  
  conf_load(argv[1]);
  printf("\x1B[40;37m\x1B[H\x1B[2J");
  printf("Configuration file loaded from %s\n", argv[1]);
  
  if (garena_init() == -1) {
    garena_perror("Garena library initialization failed");
    exit(-1);
  }
  
  signal(SIGINT, handle_quit);
  signal(SIGHUP, handle_quit);
    
  printf("Resolving server host (%s)\n", conf_getval(CONF_SERVER));
  server_ip = resolve(conf_getval(CONF_SERVER));
  if (server_ip == INADDR_NONE) {
    fprintf(stderr, "Invalid server host\n");
    exit(-1);
  }
  saddr.s_addr = server_ip;
  printf("Server host resolved to %s.\n", inet_ntoa(saddr));
 
  printf("Resolving room host (%s)\n", conf_getval(CONF_ROOM_HOST));
  room_ip = resolve(conf_getval(CONF_ROOM_HOST));
  if (room_ip == INADDR_NONE) {
    fprintf(stderr, "Invalid room host\n");
    exit(-1);
  }
  saddr.s_addr = room_ip;
  printf("Room host resolved to %s.\n", inet_ntoa(saddr));
  gateinfo.room_ip = room_ip;
  
  room_id = atoi(conf_getval(CONF_ROOM_ID));
  if ((room_id < 1) || (room_id > 0xFFFFFF)) {
    fprintf(stderr, "ROOM_ID should be an integer between 1 and %u (inclusive)\n", 0xFFFFFF);
    exit(-1);
  }
  
  gateinfo.room_id = room_id;
  
  if (conf_getval(CONF_LPORT)) {
    lport = atoi(conf_getval(CONF_LPORT));
    if ((lport < 1) || (lport > 65535)) {
      fprintf(stderr, "LPORT should be an integer between 1 and 65535 (inclusive)\n");
      exit(-1);
    }
    printf("Using non-standard local port: %u\n", lport);
  } 
    
  serv = ghl_new_serv(conf_getval(CONF_USERNAME), conf_getval(CONF_PASSWORD), server_ip, 0, lport, 0, 0 );
  if (serv == NULL) {
    garena_perror("Failed to connect to server");
    exit(-1);
  } else printf("Server connection in progress...\n");
  gateinfo.serv = serv;
  
  register_handlers(serv, &gateinfo);  

  while (!quit) {
    assert(serv);

    FD_ZERO(&fds); 
    maxfd = ghl_fill_fds(serv, &fds);
    if (ready) 
      FD_SET(0, &fds);
    if (handled) {
      printf("\x1B[1m\x1B[37mgate4dead>\x1B[22m ");
      fflush(stdout);      
      handled = 0;
    }
    
    if (ghl_fill_tv(serv, &tv) == 0) {
      r = select(maxfd+1, &fds, NULL, NULL, NULL);
    } else r = select(maxfd+1, &fds, NULL, NULL, &tv);
    
    if ((r == -1) && (errno != EINTR)) {
      perror("select");
      break;
    }
    if (r >= 0) {
      ghl_process(serv, &fds);
      if (FD_ISSET(0, &fds)) {
        r = read(0, buf, sizeof(buf));
        if (r <= 0) {
          quit = 1;
          break;
        } 
        if (buf[r-1] == '\n') {
          buf[r-1] = 0;
          handle_command(&gateinfo, buf);
          handled = 1;
        }
      }
    }
  }
  
  if (serv && serv->room) {
    ghl_togglevpn(serv->room, 0);
    ghl_leave_room(serv->room);
  }
    
  if (serv)
    ghl_free_serv(serv);
  
  garena_fini();
  conf_free(); 
  if (quit == 1) { 
    printf("\x1B[0m\x1B[H\x1B[2JBye...\n");
    return 0;
  } else return -1;
}
