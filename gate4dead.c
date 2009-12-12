
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <garena/garena.h>
#include <garena/ghl.h>
#include <garena/error.h>

#include "conf.h"

#define BLUE_BOLD "\x1B[34;1m"
#define RED_BOLD "\x1B[31;1m"
#define YELLOW_BOLD "\x1B[33;1m"
#define CYAN_BOLD "\x1B[36;1m"
#define GREEN_BOLD "\x1B[32;1m"
#define WHITE_BOLD "\x1B[37;1m"

#define WHITE "\x1B[37;22m"

#define WHITE_ON_BLACK "\x1B[40;37m"
#define CLEAR_SCR "\x1B[H\x1B[2J"
#define RESET_ATTR "\x1B[0m"

#define L4D_IP_OFFSET1 0x7D
#define L4D_IP_OFFSET2 29
#define L4D_IP_OFFSET3 33
#define L4DSERV_PORT 27015
#define MAX_FRAME 65536

#define SESSION_TIMEOUT 60
#define CHECK_INTERVAL 10

#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#define ST_FREE 0
#define ST_ACTIVE 1

typedef struct {   
  int status;
  int sock;
  ghl_member_t *member;
  int rport;
  int activity;
} session_t;

struct gateinfo_s {
  unsigned int room_ip;
  int room_id;
  unsigned int l4d_ip;
  int l4d_port;
  ghl_serv_t *serv;
};

typedef int cmdfun_t(struct gateinfo_s *gateinfo, int parc, char **parv);
typedef struct {
  cmdfun_t *fun;
  char *str;
} cmd_t;

#define MAX_CMDS 6
#define MAX_PARAMS 16

cmd_t cmdtab[];

#define MAX_STATUS 256
session_t sesstab[MAX_STATUS];

int quit = 0;
int ready = 0;

session_t *session_lookup(ghl_member_t *member, int port) {
  int i;
  for (i = 0; i < MAX_STATUS; i++) {
    if ((sesstab[i].status == ST_ACTIVE) && (sesstab[i].member == member) && (sesstab[i].rport == port)) {
      sesstab[i].activity = time(NULL);
      return (sesstab + i);
    }
  }
  return NULL;
}

int session_fill_fds(fd_set *fds) {
  int i, max = 0;
  for (i = 0; i < MAX_STATUS; i++) {
    if (sesstab[i].status == ST_ACTIVE) {
      if (sesstab[i].sock > max)
        max = sesstab[i].sock;
      FD_SET(sesstab[i].sock, fds);
    }
  }
  return max;
}

void session_close(session_t *session) {
  close(session->sock);
  session->status = ST_FREE;
}


void session_init() {
  int i ;
  for (i = 0; i < MAX_STATUS; i++) 
    sesstab[i].status = ST_FREE;
}

session_t *session_create(unsigned int servip, int servport, ghl_member_t *member , int port) {
  struct sockaddr_in fsocket;
  int i;
  int rsock;
  for (i = 0; i < MAX_STATUS; i++) {
    if (sesstab[i].status == ST_FREE) {
      rsock = socket(PF_INET, SOCK_DGRAM, 0);
      if (rsock == -1) {
        perror("socket");
        break;
      }
      fsocket.sin_family = AF_INET;
      fsocket.sin_addr.s_addr = servip;
      fsocket.sin_port = htons(servport);
      if (connect(rsock, (struct sockaddr *) &fsocket, sizeof(fsocket)) == -1) {
        perror("connect");
        break;
      }
      sesstab[i].status = ST_ACTIVE;
      sesstab[i].member = member;
      sesstab[i].rport = port;
      sesstab[i].sock = rsock;
      sesstab[i].activity = time(NULL);
      return (sesstab + i);
    }
  }
  return NULL;
}

void session_manage_timeouts() {
  int i;
  static int last_checked = 0;
  int now = time(NULL);
  if (last_checked + CHECK_INTERVAL > now)
    return;
  for (i = 0; i < MAX_STATUS; i++) {
    if ((sesstab[i].status == ST_ACTIVE) && (sesstab[i].activity + SESSION_TIMEOUT < now)) {
      session_close(sesstab + i);
    }
  }
}



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
        printf( YELLOW_BOLD "[" "\x1B[%u;%um%16s" YELLOW_BOLD "]" WHITE, color, boldness, member->name);
        pos += 19;
        total++;
      }
      if (pos > 0)
        printf("\n");
    return 0;


}

int handle_cmd_status(struct gateinfo_s *gateinfo, int parc, char **parv) {
  int i;
  struct sockaddr_in local;
  unsigned int local_len;
  char str[32];
  ghl_serv_t *serv = gateinfo->serv;
  for (i = 0; i < MAX_STATUS; i++) {
    if ((sesstab[i].status == ST_ACTIVE)) {
      local_len = sizeof(local);
      if (getsockname(sesstab[i].sock, (struct sockaddr *) &local, &local_len) == -1)
        perror("getsockname");
      if (local_len != sizeof(local))
        fprintf(stderr, "Error while getting local port\n");
      
      snprintf(str, 32, "192.168.29.%u", sesstab[i].member->virtual_suffix);
      printf(YELLOW_BOLD "%16s:%-5u " CYAN_BOLD "==>" YELLOW_BOLD " %5u " RED_BOLD " %16s " GREEN_BOLD "(%10u) " BLUE_BOLD "Act: %ld sec\n", 
             str, sesstab[i].rport, htons(local.sin_port), sesstab[i].member->name, sesstab[i].member->user_id, time(NULL) - sesstab[i].activity);    
    }
  }
  return 0;  
}

int handle_cmd_lookup(struct gateinfo_s *gateinfo, int parc, char **parv) {
  int i;
  int look_port;
  struct sockaddr_in local;
  unsigned int local_len;
  char str[32];
  if (parc != 2) {
    printf("Usage: LOOKUP <local port>\n");
    return -1;
  }
  look_port = atoi(parv[1]);
  
  for (i = 0; i < MAX_STATUS; i++) {
    if ((sesstab[i].status == ST_ACTIVE)) {
      local_len = sizeof(local);
      if (getsockname(sesstab[i].sock, (struct sockaddr *) &local, &local_len) == -1)
        perror("getsockname");
      if (local_len != sizeof(local))
        fprintf(stderr, "Error while getting local port\n");
      if (htons(local.sin_port) == look_port) {
        snprintf(str, 32, "192.168.29.%u", sesstab[i].member->virtual_suffix);
        printf(YELLOW_BOLD "%16s:%-5u " CYAN_BOLD "==>" YELLOW_BOLD " %5u " RED_BOLD " %16s " GREEN_BOLD "(%10u) " BLUE_BOLD "Act: %ld sec\n", 
               str, sesstab[i].rport, htons(local.sin_port), sesstab[i].member->name, sesstab[i].member->user_id, time(NULL) - sesstab[i].activity);    
        return 0;
      }
    }
  }
  printf("No match.\n");
  return -1;
}


int handle_cmd_whois(struct gateinfo_s *gateinfo, int parc, char **parv) {
  ghl_room_t *rh = gateinfo->serv ? gateinfo->serv->room : NULL;
  ghl_member_t *member;
  ihashitem_t iter;

  int found = 0;
  
  if (parc != 2) {
    printf("Usage: WHOIS <name|IP|ID>\n");
    return -1;
  }
  for (iter = ihash_iter(rh->members); iter; iter = ihash_next(rh->members, iter)) {
      member = ihash_val(iter);
      if  ((strcasecmp(member->name, parv[1]) == 0) ||
          (((member->virtual_suffix << 24) | inet_addr(GARENA_NETWORK)) == inet_addr(parv[1]) ) ||
          (member->external_ip.s_addr == inet_addr(parv[1])) ||
          (member->internal_ip.s_addr == inet_addr(parv[1])) ||
          (ghtonl(member->user_id) == strtoul(parv[1], NULL, 10))) {
            printf(CYAN_BOLD "+--------------------------------------\n");
            printf(CYAN_BOLD "|" WHITE " Member name      : " GREEN_BOLD "%s\n", member->name);
            printf(CYAN_BOLD "|" WHITE " User ID          : " GREEN_BOLD "%u\n", member->user_id);
            printf(CYAN_BOLD "|" WHITE " Country          : " GREEN_BOLD "%s\n", member->country);
            printf(CYAN_BOLD "|" WHITE " Level            : " BLUE_BOLD "%u\n", member->level);
            printf(CYAN_BOLD "|" WHITE " In game          : " BLUE_BOLD "%s\n", member->vpn ? "yes" : "no" );
            printf(CYAN_BOLD "|" WHITE " Virtual IP       : " YELLOW_BOLD "192.168.29.%u\n", member->virtual_suffix);
            printf(CYAN_BOLD "|" WHITE " External ip/port : " YELLOW_BOLD "%s:%u\n", inet_ntoa(member->external_ip), member->external_port);
            printf(CYAN_BOLD "|" WHITE " Internal ip/port : " YELLOW_BOLD "%s:%u\n", inet_ntoa(member->internal_ip), member->internal_port);
            if (member->conn_ok == 2) {
              printf(CYAN_BOLD "|" WHITE " Ping             : " RED_BOLD "%u msec\n", member->ping);
            } else printf(CYAN_BOLD "|" WHITE " Ping             : " RED_BOLD "N/A\n");
            printf(CYAN_BOLD "+--------------------------------------\n");
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
 {handle_cmd_status, "STATUS"},
 {handle_cmd_lookup, "LOOKUP"}
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
    printf(WHITE_BOLD "gate4dead> " WHITE);
    fflush(stdout);
  } else {
    fprintf(stderr, "Room join failed.\n");
    quit = 2;
  }
  return 0;
}

int handle_udp_encap(ghl_serv_t *serveur, int event, void *event_param, void *privdata) {
  ghl_udp_encap_t *udp_encap = event_param;
  struct gateinfo_s *gateinfo = privdata;
  session_t *session;
  int sport = udp_encap->sport;
  if (udp_encap->dport != gateinfo->l4d_port)
    return 0;
  session = session_lookup(udp_encap->member, sport);
  if (session == NULL) {
    session = session_create(gateinfo->l4d_ip, gateinfo->l4d_port, udp_encap->member, sport);
  }
  if (session != NULL)
    write(session->sock, udp_encap->payload, udp_encap->length);
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
  ghl_register_handler(serv, GHL_EV_UDP_ENCAP, handle_udp_encap, gateinfo);
}

void handle_quit(int crap) {
  quit = 1;
}

int main(int argc, char **argv) {
  unsigned int server_ip, room_ip, l4d_ip;
  struct in_addr saddr;
  int lport = 0, l4d_port = 0;
  int handled = 0;
  int room_id, maxfd, maxfd2;
  ghl_serv_t *serv;
  struct gateinfo_s gateinfo;
  fd_set fds;
  struct timeval tv;
  int i;
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
  printf( WHITE_ON_BLACK CLEAR_SCR);
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
  
  printf("Resolving L4D host (%s)\n", conf_getval(CONF_L4DSERV_HOST));
  l4d_ip = resolve(conf_getval(CONF_L4DSERV_HOST));
  if (l4d_ip == INADDR_NONE) {
    fprintf(stderr, "Invalid L4D host\n");
    exit(-1);
  }
  saddr.s_addr = l4d_ip;
  printf("L4D host resolved to %s.\n", inet_ntoa(saddr));
  gateinfo.l4d_ip = l4d_ip;
  
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

  if (conf_getval(CONF_L4DSERV_PORT)) {
    l4d_port = atoi(conf_getval(CONF_L4DSERV_PORT));
    if ((l4d_port < 1) || (l4d_port > 65535)) {
      fprintf(stderr, "L4DSERV_PORT should be an integer between 1 and 65535 (inclusive)\n");
      exit(-1);
    }
    printf("Using non-standard L4D server port: %u\n", l4d_port);
  } else l4d_port = L4DSERV_PORT;

  gateinfo.l4d_port = l4d_port;
    
  serv = ghl_new_serv(conf_getval(CONF_USERNAME), conf_getval(CONF_PASSWORD), server_ip, 0, lport, 0, 0 );
  if (serv == NULL) {
    garena_perror("Failed to connect to server");
    exit(-1);
  } else printf("Server connection in progress...\n");
  gateinfo.serv = serv;
  
  register_handlers(serv, &gateinfo);  

  while (!quit) {
    assert(serv);
    session_manage_timeouts();

    FD_ZERO(&fds); 
    maxfd = ghl_fill_fds(serv, &fds);
    if (ready) {
      FD_SET(0, &fds);
      maxfd2 = session_fill_fds(&fds);
      maxfd = MAX(maxfd, maxfd2); 
    }
    if (handled) {
      printf(WHITE_BOLD "gate4dead> " WHITE);
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
      if (!quit && FD_ISSET(0, &fds)) {
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
      if (ready) {
        for (i = 0; i < MAX_STATUS; i++) {
          session_t *session = (sesstab + i);
          if (session->status != ST_ACTIVE)
            continue;
          if (FD_ISSET(session->sock, &fds)) {
            r = read(session->sock, buf, MAX_FRAME);
            if (r > 0) {
              ghl_udp_encap(serv, session->member, l4d_port, session->rport, buf, r);
            }
          }
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
    printf(RESET_ATTR CLEAR_SCR "Bye...\n");
    return 0;
  } else return -1;
}
