#ifndef __GET_FILE_CONFIG_H__
#define __GET_FILE_CONFIG_H__
struct recv_mac
{
	char send_mac[18];
	int capture_flag;
	int send_flag;
	char capture_time[20];
	struct recv_mac *next;
}; 
extern void modify_text(char *path,char *start,char *end,char *data);
extern int get_text_data(char* src,char* start,char* end,char* target,int limit);
extern void set_config(char *path,char *key,char *value);
extern int get_config(char *path,char *key, char *value);
extern void deleteALL(struct recv_mac **p_head);
extern void link_creat_head_check( struct recv_mac **p_head, struct recv_mac *p_new);
extern struct recv_mac * link_search_mac_check( struct recv_mac *head,char *mac);
#endif
