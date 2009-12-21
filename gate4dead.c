#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
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
#include <garena/util.h>

#include "conf.h"

#define GATE4DEAD_VERSION "0.1" 

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

#define MAKE_KEY(member, port) ((((member)->virtual_suffix) << 24) | (port))

#define KEEPALIVE_INTERVAL 300
typedef struct {   
  int sock;
  ghl_member_t *member;
  int rport;
  int activity;
} session_t;

typedef struct {
  int user_id;
  char name[17];
} ban_t;

struct gateinfo_s {
  unsigned int room_ip;
  unsigned int bind_ip;
  int symmetric;
  int room_id;
  unsigned int l4d_ip;
  int l4d_port;
  unsigned int my_ip;
  char *confname;
  ghl_serv_t *serv;
  int last_ok_keepalive;
  int on;
  int restrict;
  char country[3];
};

typedef int cmdfun_t(struct gateinfo_s *gateinfo, int parc, char **parv);
typedef struct {
  cmdfun_t *fun;
  char *str;
} cmd_t;

#define MAX_CMDS 15
#define MAX_PARAMS 16

cmd_t cmdtab[];

#define MAX_SESSIONS 4096
llist_t sesstab;
ihash_t sessmap;
ihash_t banmap;

int num_sessions = 0;

int quit = 0;
int ready = 0;

session_t *session_lookup(ghl_member_t *member, int port) {
  session_t *session;
  cell_t iter;
  session = ihash_get(sessmap, MAKE_KEY(member, port));
  if (session)
    session->activity = time(NULL);
  return session;
}


int session_fill_fds(fd_set *fds) {
  int max = 0;
  session_t *session;
  cell_t iter;
  for (iter = llist_iter(sesstab); iter; iter = llist_next(iter)) {
    session = llist_val(iter);
    if (session->sock > max)
      max = session->sock;
    FD_SET(session->sock, fds);
  }
  return max;
}

int set_nonblock(int sock) {
  int flags;
  
  flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1)
    return -1;  
  return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}


void session_close(session_t *session) {
  num_sessions --;
  close(session->sock);
  llist_del_item(sesstab, session);
  ihash_del(sessmap, MAKE_KEY(session->member, session->rport));
  free(session);
}

void session_kill_member(ghl_member_t *member) {
  session_t *session;
  session_t *todel = NULL;
  cell_t iter;
  for (iter = llist_iter(sesstab); iter; iter = llist_next(iter)) {
    if (todel) {
      session_close(todel);
      todel = NULL;
    }
    session = llist_val(iter);
    if (session->member == member)
      todel = session;
  }
  if (todel)
    session_close(todel);
}

void session_init() {
  sesstab = llist_alloc();
  sessmap = ihash_init();
  if ((sesstab == NULL) || (sessmap == NULL)) {
    fprintf(stderr, "Session list creation failed\n");
    exit(-1);
  }
}

session_t *session_create(struct gateinfo_s *gateinfo, ghl_member_t *member , int port) {
  struct sockaddr_in fsocket, local;
  unsigned int servip = gateinfo->l4d_ip;
  unsigned int servport = gateinfo->l4d_port;
  int i;
  int rsock;
  session_t *session;
  if (num_sessions >= MAX_SESSIONS) {
    return NULL;
  }
  session = malloc(sizeof(session_t));
  if (session == NULL) {
    return NULL;
  }
  
  rsock = socket(PF_INET, SOCK_DGRAM, 0);
  if (rsock == -1) {
    free(session);
    perror("socket");
    return NULL;
  }
  set_nonblock(rsock);
  if (gateinfo->bind_ip != INADDR_NONE) {
    local.sin_family = AF_INET;
    if (gateinfo->symmetric) {
      local.sin_addr.s_addr = (gateinfo->bind_ip & 0x00FFFFFF) | (member->virtual_suffix << 24);
    } else local.sin_addr.s_addr = gateinfo->bind_ip;
    local.sin_port = 0;
    if (bind(rsock, (struct sockaddr *) &local, sizeof(local)) == -1) {
      free(session);
      close(rsock);
      perror("bind");
      return NULL;
    }     
  }
  fsocket.sin_family = AF_INET;
  fsocket.sin_addr.s_addr = servip;
  fsocket.sin_port = htons(servport);
  if (connect(rsock, (struct sockaddr *) &fsocket, sizeof(fsocket)) == -1) {
    free(session);
    close(rsock);
    perror("connect");
    return NULL;
  }
  session->member = member;
  session->rport = port;
  session->sock = rsock;
  session->activity = time(NULL);
  if (llist_add_head(sesstab, session) == -1) {
    free(session);
    close(rsock);
    return NULL;
  }
  if (ihash_put(sessmap, MAKE_KEY(session->member, session->rport), session) == -1) {
    llist_del_item(sesstab, session);
    free(session);
    close(rsock);
    return NULL;
  }
  num_sessions++;
  return session;
}

void session_manage_timeouts() {
  session_t *session;
  session_t *todel = NULL;
  cell_t iter;
  int now = time(NULL);
  for (iter = llist_iter(sesstab); iter; iter = llist_next(iter)) {
    if (todel) {
      session_close(todel);
      todel = NULL;
    }
    session = llist_val(iter);
    if (session->activity + SESSION_TIMEOUT < now) {
      todel = session;
    }
  }
  if (todel)
    session_close(todel);
}



int handle_cmd_help(struct gateinfo_s *gateinfo, int parc, char **parv) {
  int i;
  printf(CYAN_BOLD "Available commands:\n");
  printf(YELLOW_BOLD "HELP: " WHITE "This help message.\n");
  printf(YELLOW_BOLD "WHO: " WHITE "List the people on the room. Red people are playing, Green people are not playing, and Gray people are currently unreachable.\n");
  printf(YELLOW_BOLD "WHOIS: " WHITE "Print information on an user. You can search by name, User ID, or virtual/external/internal IP.\n");
  printf(YELLOW_BOLD "STATUS: " WHITE "Print information on gate4dead status.\n");
  printf(YELLOW_BOLD "SESSIONS: " WHITE "List active sessions.\n");
  printf(YELLOW_BOLD "LOOKUP: " WHITE "Find a session by its remapped source port\n");
  printf(YELLOW_BOLD "BAN: " WHITE "Ban an user, by account name or user ID\n");
  printf(YELLOW_BOLD "UNBAN: " WHITE "Unban an user, by account name or user ID\n");
  printf(YELLOW_BOLD "BANLIST: " WHITE "Shows the ban list\n");
  printf(YELLOW_BOLD "OFF: " WHITE "Rejects new sessions\n");
  printf(YELLOW_BOLD "ON: " WHITE "Accepts new sessions\n");
  printf(YELLOW_BOLD "SAVE: " WHITE "Save settings to file\n");
  printf(YELLOW_BOLD "RESTRICT: " WHITE "Accept sessions only from a specific country\n");
  printf(YELLOW_BOLD "UNRESTRICT: " WHITE "Accept sessions from all countries\n");
  printf(YELLOW_BOLD "QUIT: " WHITE "Quit.\n");
  return 0;
}

int handle_cmd_restrict(struct gateinfo_s *gateinfo, int parc, char **parv) {
  if (parc > 2) {
    printf("usage: RESTRICT [<country>]\n");
    return -1;
  }
  if (parc == 1) 
  {
    if (gateinfo->restrict) {
      printf(CYAN_BOLD "Currently restricted to: " GREEN_BOLD "%s\n", gateinfo->country); 
    } else printf( CYAN_BOLD "Currently unrestricted\n");
  }
  if (parc == 2) {
    gateinfo->restrict = 1;
    strncpy(gateinfo->country, parv[1], 2);
    gateinfo->country[2] = 0; 
  }
}
int handle_cmd_unrestrict(struct gateinfo_s *gateinfo, int parc, char **parv) {
  gateinfo->restrict = 0;
}

int handle_cmd_ban(struct gateinfo_s *gateinfo, int parc, char **parv) {
  ihashitem_t iter;
  ihash_t members = gateinfo->serv->room->members;
  ghl_member_t *member;
  ban_t *ban;
  if (parc != 2) {
    printf("Usage: BAN <username|userid>\n");
    return -1;
  }
  for (iter = ihash_iter(members); iter; iter = ihash_next(members, iter)) {
    member = ihash_val(iter);
    if ((strcasecmp(member->name, parv[1]) == 0) || (strtoul(parv[1], NULL, 10) == member->user_id)) {
      if (ihash_get(banmap, member->user_id) != NULL) {
        fprintf(stderr, "This user is already banned\n");
        return -1;
      }
      ban = malloc(sizeof(ban_t));
      if (ban == NULL) {
        fprintf(stderr, "Ban creation failed\n");
        return -1;
      }
      ban->user_id = member->user_id;
      strncpy(ban->name, member->name, 16);
      ban->name[16] = 0;
      ihash_put(banmap, member->user_id, ban);
      session_kill_member(member);
      printf("Ban user " RED_BOLD "%s" GREEN_BOLD " (%u)\n", member->name, member->user_id);
      return 0;
    }
  }
  printf("User not found.\n");
  return -1;
}

int handle_cmd_unban(struct gateinfo_s *gateinfo, int parc, char **parv) {
  ban_t *ban;
  ihashitem_t iter;
  if (parc != 2) {
    printf("Usage: UNBAN <username|userid>\n");
    return -1;
  }
  for (iter = ihash_iter(banmap); iter; iter = ihash_next(banmap, iter)) {
    ban = ihash_val(iter);
    if ((strcasecmp(ban->name, parv[1]) == 0) || (atoi(parv[1]) == ban->user_id)) {
      printf("Unbanning user " RED_BOLD "%s" GREEN_BOLD " (%u)\n", ban->name, ban->user_id);
      ihash_del(banmap, ban->user_id);
      free(ban);
      return 0;
    }
  }
  printf("Ban not found.\n");
  return -1;
}

int handle_cmd_banlist(struct gateinfo_s *gateinfo, int parc, char **parv) {
  ban_t *ban;
  ihashitem_t iter;
  printf(CYAN_BOLD "---=== Ban list ===---\n");
  for (iter = ihash_iter(banmap); iter; iter = ihash_next(banmap, iter)) {
    ban = ihash_val(iter);
    printf(YELLOW_BOLD "BAN: " WHITE "user " RED_BOLD "%s" GREEN_BOLD " (%u)\n", ban->name, ban->user_id);
  }
  printf(CYAN_BOLD "---================---\n");
  return 0;
}

int handle_cmd_save(struct gateinfo_s *gateinfo, int parc, char **parv) {
  FILE *f;
  ban_t *ban;
  ihashitem_t iter;
  printf("Saving banlist file...\n");
  if (conf_getval(CONF_BANLIST_FILE) == NULL) {
    fprintf(stderr, "Can't save banlist, no banlist file defined\n");
    return -1;
  }
  f = fopen(conf_getval(CONF_BANLIST_FILE), "w");
  if (f == NULL) {
    fprintf(stderr, "Can't open banlist file\n");
    return -1;  
  }
  for (iter = ihash_iter(banmap); iter; iter = ihash_next(banmap, iter)) {
    ban = ihash_val(iter);
    if (fwrite(ban, sizeof(ban_t), 1, f) != 1) {
      fprintf(stderr, "Banlist file write failed\n");
      fclose(f);
      return -1;
    }
  }
  fclose(f);
  printf("Settings saved.\n");
  return 0;
}

void banlist_load() {
  FILE *f;
  ban_t *ban;
  if (conf_getval(CONF_BANLIST_FILE) == NULL) {
    return;
  }
  f = fopen(conf_getval(CONF_BANLIST_FILE), "r");
  if (f == NULL) {
    return;
  }
  
  for (;;) {
    ban = malloc(sizeof(ban_t));
    if (ban == NULL) {
      fprintf(stderr, "Ban allocation failed while loading ban list\n");
      fclose(f);
      return;
    }
    if (fread(ban, sizeof(ban_t), 1, f) != 1) {
      free(ban);
      fclose(f);
      return;
    }
    ban->name[16] = 0;
    ihash_put(banmap, ban->user_id, ban);
  }
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
  struct in_addr saddr;
  cell_t iter;
  session_t *session;
  char str[32];
  ghl_serv_t *serv = gateinfo->serv;
  printf(CYAN_BOLD "+---------------------------------------------------\n");

  printf(CYAN_BOLD "| " WHITE "Logged as                     : " BLUE_BOLD "%s (%u)\n", serv->my_info.name, serv->my_info.user_id); 
  printf(CYAN_BOLD "| " WHITE "My virtual IP                 : " YELLOW_BOLD "192.168.29.%u\n", serv->room->me->virtual_suffix);
  saddr.s_addr = gateinfo->bind_ip;
  printf(CYAN_BOLD "| " WHITE "My bind IP                    : " YELLOW_BOLD "%s\n", inet_ntoa(saddr));
  saddr.s_addr = gateinfo->l4d_ip;
  printf(CYAN_BOLD "| " WHITE "L4D server IP                 : " YELLOW_BOLD "%s\n", inet_ntoa(saddr));
  printf(CYAN_BOLD "| " WHITE "Using config file             : " BLUE_BOLD "%s\n", gateinfo->confname);
  printf(CYAN_BOLD "| " WHITE "Symmetric address translation : " BLUE_BOLD "%s\n", gateinfo->symmetric ? "enabled" : "disabled" );
  printf(CYAN_BOLD "| " WHITE "Accepting new sessions        : " BLUE_BOLD "%s\n", gateinfo->on ? "yes" : "no" );
  if (gateinfo->last_ok_keepalive) {
    printf(CYAN_BOLD "| " WHITE "Last successful keep-alive    : " RED_BOLD "%ld\n", time(NULL) - gateinfo->last_ok_keepalive);
  } else {
    printf(CYAN_BOLD "| " WHITE "Last successful keep-alive    : " RED_BOLD "N/A\n");
  }
  printf(CYAN_BOLD "+---------------------------------------------------\n");

  return 0;  
}


int handle_cmd_sessions(struct gateinfo_s *gateinfo, int parc, char **parv) {
  int i;
  struct sockaddr_in local;
  unsigned int local_len;
  cell_t iter;
  session_t *session;
  char str[32];
  ghl_serv_t *serv = gateinfo->serv;
  printf( CYAN_BOLD "--==[ Session list ]==--\n");
  for (iter = llist_iter(sesstab); iter; iter = llist_next(iter)) {
    session = llist_val(iter);

    local_len = sizeof(local);
    if (getsockname(session->sock, (struct sockaddr *) &local, &local_len) == -1)
      perror("getsockname");
    if (local_len != sizeof(local))
      fprintf(stderr, "Error while getting local port\n");
      
    snprintf(str, 32, "192.168.29.%u", session->member->virtual_suffix);
    printf(YELLOW_BOLD "%16s:%-5u " CYAN_BOLD "==>" YELLOW_BOLD " %5u " RED_BOLD " %16s " GREEN_BOLD "(%10u) " BLUE_BOLD "Act: %ld sec\n", 
             str, session->rport, htons(local.sin_port), session->member->name, session->member->user_id, time(NULL) - session->activity);    
  }
  printf( CYAN_BOLD "--====================--\n");
  return 0;  
}

int handle_cmd_lookup(struct gateinfo_s *gateinfo, int parc, char **parv) {
  int i;
  int look_port;
  struct sockaddr_in local;
  cell_t iter;
  session_t *session;
  unsigned int local_len;
  char str[32];
  if (parc != 2) {
    printf("Usage: LOOKUP <local port>\n");
    return -1;
  }
  look_port = atoi(parv[1]);
  for (iter = llist_iter(sesstab); iter; iter = llist_next(iter)) {
    session = llist_val(iter);
    local_len = sizeof(local);
    if (getsockname(session->sock, (struct sockaddr *) &local, &local_len) == -1)
      perror("getsockname");
    if (local_len != sizeof(local))
      fprintf(stderr, "Error while getting local port\n");
    if (htons(local.sin_port) == look_port) {
      snprintf(str, 32, "192.168.29.%u", session->member->virtual_suffix);
      printf(YELLOW_BOLD "%16s:%-5u " CYAN_BOLD "==>" YELLOW_BOLD " %5u " RED_BOLD " %16s " GREEN_BOLD "(%10u) " BLUE_BOLD "Act: %ld sec\n", 
               str, session->rport, htons(local.sin_port), session->member->name, session->member->user_id, time(NULL) - session->activity);    
      return 0;
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

int handle_cmd_off(struct gateinfo_s *gateinfo, int parc, char **parv) {
  printf("Now refusing new sessions\n");
  gateinfo->on = 0;
}

int handle_cmd_on(struct gateinfo_s *gateinfo, int parc, char **parv) {
  printf("Now accepting new sessions\n");
  gateinfo->on = 1;
}

int handle_cmd_quit(struct gateinfo_s *gateinfo, int parc, char **parv) {
  handle_cmd_save(gateinfo, parc, parv);
  quit = 1;
  return 0;
}


cmd_t cmdtab[MAX_CMDS] = {
 {handle_cmd_help, "HELP"},
 {handle_cmd_who, "WHO"},
 {handle_cmd_whois, "WHOIS"},
 {handle_cmd_quit, "QUIT"},
 {handle_cmd_status, "STATUS"},
 {handle_cmd_sessions, "SESSIONS"},
 {handle_cmd_lookup, "LOOKUP"},
 {handle_cmd_ban, "BAN"},
 {handle_cmd_unban, "UNBAN"},
 {handle_cmd_banlist, "BANLIST"},
 {handle_cmd_on, "ON"},
 {handle_cmd_off, "OFF"},
 {handle_cmd_restrict, "RESTRICT"},
 {handle_cmd_unrestrict, "UNRESTRICT"},
 {handle_cmd_save, "SAVE"}
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
    gateinfo->my_ip = (serv->room->me->virtual_suffix << 24) | inet_addr(GARENA_NETWORK);
    printf(WHITE_BOLD "gate4dead> " WHITE);
    fflush(stdout);
  } else {
    fprintf(stderr, "Room join failed.\n");
    quit = 2;
  }
  return 0;
}

int handle_togglevpn(ghl_serv_t *serveur, int event, void *event_param, void *privdata) {
  ghl_togglevpn_t *togglevpn = event_param;
  struct gateinfo_s *gateinfo = privdata;
  if (togglevpn->member->user_id == gateinfo->serv->my_info.user_id) {
    gateinfo->last_ok_keepalive = time(NULL);
  }
  return 0;
}

int handle_part(ghl_serv_t *serveur, int event, void *event_param, void *privdata) {
  ghl_part_t *part = event_param; 
  session_kill_member(part->member);
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
  if ((session == NULL) && (ihash_get(banmap, udp_encap->member->user_id) == NULL) && ((gateinfo->restrict == 0) || (strncasecmp(udp_encap->member->country, gateinfo->country,2)==0)) && (gateinfo->on)) {
    session = session_create(gateinfo,  udp_encap->member, sport);
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
  ghl_register_handler(serv, GHL_EV_PART, handle_part, gateinfo);
  ghl_register_handler(serv, GHL_EV_TOGGLEVPN, handle_togglevpn, gateinfo);
}


void l4d_translate(struct gateinfo_s *gateinfo, char *buf, int size) {
  unsigned int routing_host = gateinfo->l4d_ip;
  unsigned int routing_host_r = htonl(routing_host);
  unsigned int myip = gateinfo->my_ip;
  unsigned int myip_r = htonl(myip);

  if (memcmp(buf + L4D_IP_OFFSET1, &routing_host, 4) == 0) {
            IFDEBUG(printf("[NET] Translated announcement packet.(1)\n"));
            memcpy(buf + L4D_IP_OFFSET1, &myip, 4);
          }
          if (memcmp(buf + L4D_IP_OFFSET2, &routing_host_r, 4) == 0) {
            IFDEBUG(printf("[NET] Translated announcement packet(2).\n"));
            memcpy(buf + L4D_IP_OFFSET2, &myip_r, 4);
          }
          if (memcmp(buf + L4D_IP_OFFSET3, &routing_host_r, 4) == 0) {
            IFDEBUG(printf("[NET] Translated announcement packet(3).\n"));
            memcpy(buf + L4D_IP_OFFSET3, &myip_r, 4);
          }

}

int main(int argc, char **argv) {
  unsigned int server_ip, room_ip, l4d_ip, bind_ip;
  struct in_addr saddr;
  int last_keepalive, last_timeout_check, now;
  int lport = 0, l4d_port = 0;
  int handled = 0;
  int symmetric;
  int room_id, maxfd, maxfd2;
  ghl_serv_t *serv;
  struct gateinfo_s gateinfo;
  fd_set fds;
  struct timeval tv;
  int i;
  int r;
  char buf[MAX_FRAME];
  
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
  printf( WHITE_BOLD "gate4dead " WHITE "version " RED_BOLD "%s" WHITE " starting...\n", GATE4DEAD_VERSION);
  printf("Configuration file loaded from %s\n", argv[1]);
  gateinfo.confname = argv[1];
  
  if (garena_init() == -1) {
    garena_perror("Garena library initialization failed");
    exit(-1);
  }
  
  signal(SIGINT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
    
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
  
  if (conf_getval(CONF_BIND_HOST)) {
    printf("Resolving bind host (%s)\n", conf_getval(CONF_BIND_HOST));
    bind_ip = resolve(conf_getval(CONF_BIND_HOST));
    if (bind_ip == INADDR_NONE) {
      fprintf(stderr, "Invalid bind host\n");
      exit(-1);
    }
    saddr.s_addr = bind_ip;
    printf("bind host resolved to %s.\n", inet_ntoa(saddr));
  } else bind_ip = INADDR_NONE;
  gateinfo.bind_ip = bind_ip;
  
  if (conf_getval(CONF_SYMMETRIC) && atoi(conf_getval(CONF_SYMMETRIC))) {
    if (bind_ip == INADDR_NONE) {
      fprintf(stderr, "Symmetric address translation require BIND_HOST parameter.\n");
      exit(-1);
    }
    symmetric = 1;
  } else symmetric = 0;
  gateinfo.symmetric = symmetric;
  
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
  
  gateinfo.on = 1;
  gateinfo.restrict = 0;
  
  session_init();
  banmap = ihash_init();
  banlist_load();
  
  if (banmap == NULL) {
    fprintf(stderr, "Ban list allocation failed\n");
    exit(-1);
  }
  register_handlers(serv, &gateinfo);  
  last_keepalive = time(NULL);
  last_timeout_check = last_keepalive;
  gateinfo.last_ok_keepalive = last_keepalive;
  set_nonblock(0);
  while (!quit) {
    assert(serv);
    now = time(NULL);
    if ((last_timeout_check + CHECK_INTERVAL) < now) {
      session_manage_timeouts();
      last_timeout_check = now;
    }
    if ((last_keepalive + KEEPALIVE_INTERVAL) < now) {
      last_keepalive = now;
      ghl_togglevpn(serv->room, 1);
    }
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
      if (quit)
        break;
      if (FD_ISSET(0, &fds)) {
        r = read(0, buf, sizeof(buf));
        if ((r == 0) || ((r == -1) && (errno != EINTR))) {
          quit = 1;
          break;
        } 
        if ((r > 0) && (buf[r-1] == '\n')) {
          buf[r-1] = 0;
          handle_command(&gateinfo, buf);
          handled = 1;
        }
      }
      if (ready) {
        cell_t iter;
        session_t *session;
        for (iter = llist_iter(sesstab); iter; iter = llist_next(iter)) {
          session = llist_val(iter);
          if (FD_ISSET(session->sock, &fds)) {
            r = read(session->sock, buf, MAX_FRAME);
            if (r > 0) {
              l4d_translate(&gateinfo, buf, r);
              ghl_udp_encap(serv, session->member, l4d_port, session->rport, buf, r);
            }
          }
        } 
      } 
    }
    if (ready && ((gateinfo.last_ok_keepalive + (3*KEEPALIVE_INTERVAL)) < time(NULL))) {
      fprintf(stderr, "Room server timed out.\n");
      quit = 2;
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
  
  llist_free_val(sesstab);
  ihash_free(sessmap);
  ihash_free_val(banmap);
  if (quit == 1) { 
    printf(RESET_ATTR CLEAR_SCR "Bye...\n");
    return 0;
  } else return -1;
}
