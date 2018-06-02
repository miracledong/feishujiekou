#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define _GNU_SOURCE
#include <string.h>

#include "get_file_config.h"
//#define file_path  "/var/tmp/disk/mmcblk0/boyi_app/config.txt"
//#define file_path  "./config.txt"

void modify_text(char *path,char *start,char *end,char *data)
{
	char buf[100] = {'\0'};
	sprintf(buf,"%s%s%s",start,data,end);
	FILE *fp = fopen(path,"w");
    fputs(buf,fp);
    fclose(fp);
}

int get_text_data(char* src,char* start,char* end,char* target,int limit)
{
    char *pos1=NULL,*pos2=NULL;
    
    pos1=(char *)strcasestr(src,start);
    if(pos1){
        pos1+=strlen(start);
        pos2 = (char *)strcasestr(pos1, end);
        
        if(pos2==NULL)
            pos2 = strlen(src)+src;
        
        if(pos2&&(pos2-pos1<limit)){
            memcpy(target, pos1, pos2-pos1);
        }
    }
    return 1;
}



void set_config(char *path,char *key,char *value)
{
	char start[100] = {'\0'};
	sprintf(start,"\"%s\":\"",key);
	modify_text(path,start,"\"\r",value);
}
int get_config(char *path,char *key, char *value)//从config.txt中获取配置信息 yl修改，修改之后配置文件只有config.txt,升级包带版本versionLoad.txt
{
	char line[200] = {'\0'};
	char identify[200] = {'\0'};
	char line_key[100] = {'\0'};
	FILE *fp = fopen(path,"r");
	if(fp == NULL)
	{
		perror("open file failed!\n");
		return;
	}
	while(fgets(line,sizeof(line),fp))
	{
		memset(line_key,0,sizeof(line_key));
		get_text_data(line,"\"","\":",line_key,sizeof(line_key));
		if(strcmp(line_key,key) == 0)
		{
			get_text_data(line,"\":\"","\"",identify,sizeof(identify));
			strcpy(value,identify);
			fclose(fp)	;
			return 0;
		}

	}
	fclose(fp);
	return 1;
}
/* ***********************************************
 * *功能：遍历mac链表函数是否有mac：struct recv_mac * link_search_mac( struct recv_mac *head,char *mac)
 * *参数：	链表的头节点 struct recv_mac *head
 *		需要查找的mac：char *mac
 *		*返回值：找到返回对应的节点，找不到返回NULL；
 *		*************************************************/
struct recv_mac * link_search_mac_check( struct recv_mac *head,char *mac)
{
	struct recv_mac *p_mov;
	p_mov = head;

	while(p_mov)
	{
		if(strncmp(p_mov->send_mac,mac,17) == 0)//找到了
		{
			return p_mov;
		}
		p_mov = p_mov->next;
	}
	return NULL;//没有找到
}
void link_creat_head_check( struct recv_mac **p_head, struct recv_mac *p_new)
{
	struct recv_mac *p_mov=*p_head;
	if(*p_head == NULL)				/* 当第一次加入链表为空时，head执行p_new*/
		*p_head = p_new;
	else	/* 第二次及以后加入链表*/
	{		
		while(p_mov->next)
			p_mov = p_mov->next;	/* 找到原有链表的最后一个节点*/
		p_mov->next = p_new;		/* 将新申请的节点加入链表*/
	}
	p_new->next = NULL;
	return;
}
void deleteALL(struct recv_mac **p_head)
{
	struct recv_mac *pb=*p_head;
	struct recv_mac *pf=*p_head;
	
	while(pb != NULL)
	{
		pf=pb;
		pb=pb->next;
		free(pf);
	}
	return ;
}
