/* ************************************************************************
 *       Filename:  newmain.c
 *    Description:  
 *        Version:  1.0
 *        Created:  2018年03月29日 11时15分09秒
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  YOUR NAME (), 
 *        Company:  
 * ************************************************************************/

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <syslog.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
//取mac
#include <sys/types.h>     
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/time.h>
extern int h_errno;
#include "cJSON.h"
#include "info.h"

#define SEND_BUFF_SIZE 1000
#define SNF_ARRY_SIZE 1000
#define SNF_BUF_SIZE 512

#define USER_LOGIN_PORT 50001
#define USER_CHECK_IN_PORT 50003
#define DATA_COUNT_MAX 4999

#define RAW_PACKAGE 1 //定义网络大小端
//#define BOYI_APP_VERSION "getwifiinfo_050706"

#define B0(a) (a & 0xFF)
#define B1(a) (a >> 8 & 0xFF)
#define B2(a) (a >> 16 & 0xFF)
#define B3(a) (a >> 24 & 0xFF)

#define Big_Little(x) \
	((((unsigned long)x & 0xff) << 24) | \
	 (((unsigned long)x & 0xff00) << 8) | \
	 (((unsigned long)x & 0xff0000) >> 8) | \
	 (((unsigned long)x & 0xff000000) >> 24))

//#define YUNNAN 1
#define FTP_DATA 1
unsigned int SERVER_DATA_PORT = 18190;
//unsigned int SERVER_DATA_TRACK_PORT = 0;
char UnitCode[20];
char CenterIP[20];
char APid[22];
char longde[12];
char latde[12];
char longde_get[12];
char latde_get[12];
char network_card[12];
int printf_info = 0;
char SOURCE[3];
char security_vendor_code[10];
char locator_site_type[3];
char province_code[7]  = {'\0'};
char doc_version[32]  = {'\0'};
char locator_dev_type[2] = {'\0'};
int  sendtrack_time = 600;
//static char* ftp_conf = "/disk/boyi_app/ftp_base.conf";

pthread_mutex_t mymutex = PTHREAD_MUTEX_INITIALIZER; /*互斥锁*/
unsigned int UniqID = 0;
unsigned int UniqID_two = 0;
static int ap_count = 0;
static int sta_count = 0;
struct recv_mac *mac_head ;
pthread_mutex_t  mac_mx_sort;

char longde_get[12];
char latde_get[12];
pthread_mutex_t  lnglat_mx_sort;
//unsigned char key_value[9];
//unsigned char iv_value[9];
unsigned long int ap_toal =0 ;
unsigned long int sta_toal =0 ;
unsigned long int virtual_toal = 0;

char BOYI_APP_VERSION[31];
unsigned long  send_data_time = 0;
unsigned long  send_data_toal = 0;
char send_mode[10] = "";
short int run_stop =0;
unsigned int packet_need_to_deal = 0;
struct sniffer_data snf_data_arry[SNF_ARRY_SIZE];

unsigned char send_data[1514] = "";
int	head_len = 14;
char ip_config[100] = "";

struct virtual_true_type
{
	char id_type[16];
	char id[128];
};
struct virtual_type
{
	char local_type[10];
	char qzt_type[10];
};
struct virtual_type virtual_types[] = 
{
	{"1001", "1030001"},
	{"7021", "1030036"},
	{"1016", "1220007"},
	{"2141", "1330001"},
	{"9203", "1520001"},
	{"7313", "1220040"},
	{"7412", "1520002"},
	{"1095", "1420036"},
	{"7310", "1220002"},

	{"3044", "1300004"},
	{"2212", "1430001"},

	{"7189", "8000071"},
	{"7324", "1030047"},	
	{"7239", "1129999"},

	{"9999", "1380004"},
	{"1154", "1420055"}
	//{"7239", "1129999"},
	//{"7239", "1129999"},
	//{"7239", "1129999"},
	//{"1016", "0"}
};

unsigned char a2x(const char c)
{
	switch(c) {
		case '0'...'9':
			return (unsigned char)atoi(&c);
		case 'a'...'f':
			return 0xa + (c-'a');
		case 'A'...'F':
			return 0xa + (c-'A');
		default:
			goto error;
	}
error:
	printf("errno ;  \n");;
}

/*convert a string,which length is 18, to a macaddress data type.*/
#define MAC_LEN_IN_BYTE 6
#define COPY_STR2MAC(mac,str)  \
	int i; \
do { \
	for(i = 0; i < MAC_LEN_IN_BYTE; i++) {\
		mac[i] = (a2x(str[i*3]) << 4) + a2x(str[i*3 + 1]);\
	}\
} while(0)

void make_mac_del_colon(char *mac,char *mac_t)
{
	int i = 0,j = 0;
	for(;i<17;i++)
	{
		if(i != 2 && i != 5 && i != 8 && i != 11 && i != 14)
		{
			mac[j] = tolower(mac_t[i]);
			j++;
		}
	}
	return ;
}


char* get_vitual_type(char* local_type)
{
	int num = sizeof(virtual_types) / sizeof(struct virtual_type);
	int i = 0;

	for( ; i < num; i++)
	{
		if(strcmp(local_type, virtual_types[i].local_type) == 0)
		{
			return virtual_types[i].qzt_type;
		}
	}
	return NULL;
}

int malloc_sniffer_buffer(struct sniffer_data* sniffer_data, int arry_size)
{
	int i = 0;
	int res = 0;
	if (arry_size < 1)
		return -1;

	for (i = 0; i < arry_size; i++)
	{
		sniffer_data[i].buffer = (unsigned char *) malloc(SNF_BUF_SIZE);

		res = pthread_mutex_init(&sniffer_data[i].mutex, NULL);
		if (res != 0)
		{
			printf("Create %d pthread_mutex_init fail\n");
			break;
		}
	}

	return res;
}

int strsplit(char ***dest, int *count, char *s_str, char **separator, int number_separators, int compress_separator, int keep_separator) 
{ 
	int i = 0;     
	char **result = NULL;    
	char **temp_result = NULL;     
	unsigned int curt_size = 0;     
	unsigned int new_size = 0;     
	char *look_ahead = NULL;     
	char *most_front_separator_start = NULL;     
	char *most_front_separator_end = NULL;     
	char *separator_start = NULL;     
	int find_a_separator = 0;     
	int find_a_string = 0; 
	*count = 0;     
	*dest = NULL; 
	/*  check parameters */    
	if (dest == NULL|| s_str == NULL || *s_str == '\0'|| separator == NULL|| number_separators <= 0|| compress_separator < 0|| keep_separator < 0)         
		return -1; 
	for (i = 0; i < number_separators; i++)         
		if (separator[i] == NULL || *separator[i] == '\0')             
			return -1; 
	for (look_ahead = s_str; *look_ahead != '\0'; look_ahead = most_front_separator_end)     
	{	
		most_front_separator_start = look_ahead + strlen(look_ahead);        
		most_front_separator_end = look_ahead + strlen(look_ahead);         
		find_a_separator = 0; 
		/*  find the next separator. */        
		for (i = 0; i < number_separators; i++)         
		{             
			separator_start = strstr(look_ahead, separator[i]);             
			if (separator_start == NULL)                 
				continue;               
			find_a_separator = 1;             
			/*  update the most front separator. */            
			if (separator_start < most_front_separator_start)             
			{                
				most_front_separator_start = separator_start;                 
				most_front_separator_end = most_front_separator_start + strlen(separator[i]);             
			}         
		} 
		find_a_string = (look_ahead == most_front_separator_start) ? 0 : 1;           
		/*  allow put the new string into result if need. */        
		new_size = (find_a_string > 0) ? (curt_size + 1) : ((compress_separator > 0) ? curt_size : (curt_size + 1));         
		/*  allow put the separator into result if need. */        
		new_size = (keep_separator > 0) ? (new_size + 1) : new_size;         
		if (new_size == curt_size)             
			continue; 
		temp_result = (char **)malloc((new_size) * sizeof(char *));         
		if (temp_result == NULL)         
		{             
			if (result != NULL)             
			{                 
				for (i = 0; i < curt_size; i++)                     
					if (result[i] != NULL)                         
						free(result[i]);                 
				free(result);                 
				result = NULL;             
			}               
			return -2;         
		} 
		/*  copy the pointers of string find early. */        
		memset(temp_result, 0, new_size);         
		for (i = 0; i < curt_size; i++)             
			temp_result[i] = result[i]; 
		if (find_a_string == 0)         
		{             
			if (compress_separator == 0)             
			{                 
				temp_result[curt_size] = (char *)malloc(sizeof(char));                 
				if (temp_result[curt_size] == NULL)                 
				{                     
					if (temp_result != NULL)                     
					{                         
						for (i = 0; i < curt_size; i++)                             
							if (temp_result[i] != NULL)                                 
								free(temp_result[i]);                         
						free(temp_result);                         
						temp_result = NULL;                     
					}                       
					return -2;                 
				}                 
				memset(temp_result[curt_size], 0, 1);            
			}         
		}  
		else        
		{             
			/*  put the new string into result. */            
			temp_result[curt_size] = (char *)malloc((most_front_separator_start - look_ahead + 1) * sizeof(char));             
			if (temp_result[curt_size] == NULL)             
			{                 
				if (temp_result != NULL)                 
				{                     
					for (i = 0; i < curt_size; i++)                         
						if (temp_result[i] != NULL)                              
							free(temp_result[i]);                     
					free(temp_result);                     
					temp_result = NULL;                 
				}                   
				return -2;             
			}             
			memset(temp_result[curt_size], 0, most_front_separator_start - look_ahead + 1);             
			strncpy(temp_result[curt_size], look_ahead, most_front_separator_start - look_ahead);             
			temp_result[curt_size][most_front_separator_start - look_ahead] = '\0';         
		} 
		if (keep_separator > 0)         
		{                
			/*  put the separator into result. */            
			temp_result[new_size - 1] = (char *)malloc(most_front_separator_end - most_front_separator_start + 1);             
			if (temp_result[new_size - 1] == NULL)             
			{                 
				if (temp_result != NULL)                 
				{                     
					for (i = 0; i < new_size - 1; i++)                         
						if (temp_result[i] != NULL)                              
							free(temp_result[i]);                     
					free(temp_result);                     
					temp_result = NULL;                 
				}                   
				return -2;             
			}             
			memset(temp_result[new_size - 1], 0, most_front_separator_end - most_front_separator_start + 1);             
			strncpy(temp_result[new_size - 1], most_front_separator_start, most_front_separator_end - most_front_separator_start);             
			temp_result[new_size - 1][most_front_separator_end - most_front_separator_start] = '\0';         
		} 
		/*  update result. */        
		free(result);         
		result = temp_result;         
		temp_result = NULL;         
		curt_size = new_size;     
	}       
	*dest = result;     
	*count = curt_size;           
	return 0; 

}
int hostToIp(char *hostname,char *ip_config)
{
	char **pptr;
	struct hostent *hptr;
	char str[20] = {'\0'};

	if((hptr = gethostbyname(hostname)) == NULL)
	{
		printf("host to ip error!\n");
		return 1;
	}

	switch(hptr->h_addrtype)
	{
		case AF_INET:
			pptr = hptr->h_addr_list;
			for(; *pptr != NULL; pptr++){
				printf("\taddress: %s\n", inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
				sprintf(ip_config,"%s",inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
				return 0;
			}
			break;
		default:
			printf("unknown address type!\n");
			break;
	}
	return 1;
}

void send_tcp(char *ip_str, int port,int data_size)
{
	printf("TCP -----IP:%s------port:%d\n",ip_str,port);
	struct sockaddr_in  server_address;
	char buffer[1514]="";

	int send_flag = 0;
	int sockc = socket(AF_INET,SOCK_STREAM,0);
	int ret = 0, outlen = 0;
	int len = sizeof(server_address);
	int flags = fcntl(sockc, F_GETFL, 0);
	char *send_flage;
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(ip_str);
	server_address.sin_port = htons(port);

	memcpy(buffer,send_data,data_size);
	printf("send len = %d\n",data_size);
	struct timeval timeout={3,0};
	socklen_t timeout_len = sizeof(timeout);
	setsockopt(sockc, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeout_len);
	fcntl(sockc, F_SETFL, flags | O_NONBLOCK);
#if 1
	do
	{
		if (connect(sockc, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
		{
			if(errno != EINPROGRESS && errno != EWOULDBLOCK) 
			{
				printf("tcp connect error: %s\n", strerror(errno));
				break; 
			}
			struct timeval tm;
			tm.tv_sec = 5;
			tm.tv_usec = 0;
			fd_set wset;
			FD_ZERO(&wset); 
			FD_SET(sockc, &wset); 
			int n = select(sockc+1, NULL, &wset, NULL, &tm);
			if(n < 0) 
			{ 
				perror("select()"); 
				break;
			} 
			else if (0 == n) 
			{
				printf("sendTCPmsg connect timeout!\n");
				break;
			} 
			else if (1 == n)
			{
				int err;
				socklen_t socklen = sizeof(err);
				int sockoptret = getsockopt(sockc, SOL_SOCKET, SO_ERROR, &err, &socklen);
				if (sockoptret == -1)
				{
					perror("getsockopt err");
					break;
				}
				if (err == 0)
				{
					send_flag = 1;
					printf("sendTCPmsg connect success!\n");
					break;
				}
				else
				{
					errno = err;
					printf("error: %s\n", strerror(errno));
					break;
				}
				printf("sendTCPmsg connect success!\n");
			}
		}
	}while(0);
#endif
	errno=0;
	//printf("tcp size = %d\n",data_size);
	if(send_flag)
	{
		ret = send(sockc,buffer,data_size,0);
		if(ret == -1)
		printf("tcp send error: %s\n", strerror(errno));
	}
	memset(buffer, 0, 1514);
	close(sockc);
	return;
}
void fill_sub_info(Panssenger_info *panssenger_info,unsigned short type,unsigned short len,char * data)
{

	panssenger_info->cap_sub_data[panssenger_info->sub_data_num].sub_type = type;
	panssenger_info->cap_sub_data[panssenger_info->sub_data_num].sub_data_len = len;
	panssenger_info->data_size += len;
	panssenger_info->data_size += sizeof(type);
	panssenger_info->data_size += sizeof(len);
	panssenger_info->cap_sub_data[panssenger_info->sub_data_num].content_data = (char *)malloc(len);
	strncpy(panssenger_info->cap_sub_data[panssenger_info->sub_data_num].content_data,data,len);
	panssenger_info->sub_data_num++;
}

void print_data(Panssenger_info * data)
{

	Panssenger_info * panssenger_info = data;
	printf("version = %d\n", panssenger_info->head_data.version);
	printf("device_flag = %02x:%02x:%02x:%02x:%02x:%02x\n",\
			panssenger_info->head_data.device_flag[0],panssenger_info->head_data.device_flag[1],panssenger_info->head_data.device_flag[2],\
			panssenger_info->head_data.device_flag[3],panssenger_info->head_data.device_flag[4],panssenger_info->head_data.device_flag[5]);
	printf("data_type = %d\n",panssenger_info->head_data.data_type);
	printf("data_length = %d\n",panssenger_info->head_data.data_length);		

	printf("sub_type=%d\n",panssenger_info->cap_data.sub_type);
	printf("term_type=%d\n",panssenger_info->cap_data.term_type);
	printf("term_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",\
			panssenger_info->cap_data.term_mac[0],panssenger_info->cap_data.term_mac[1],panssenger_info->cap_data.term_mac[2],\
			panssenger_info->cap_data.term_mac[3],panssenger_info->cap_data.term_mac[4],panssenger_info->cap_data.term_mac[5]);
	unsigned short signal = 0;
	memcpy(&signal,&panssenger_info->cap_data.term_signal,sizeof(panssenger_info->cap_data.term_signal));
	printf("term_signal=%d\n",ntohs(signal));
	printf("cap_time=%d\n",panssenger_info->cap_data.cap_time);


	//cap_sub_data = cap_data->sub_data;
	printf("panssenger_info->sub_data_num=%d\n",panssenger_info->sub_data_num);
#if 1
	int i = 0;
	int kind = 0;
	for(kind=0;kind<=panssenger_info->sub_data_num;kind++)
	{
		printf("---------------------\n");
		printf("sub_type=%d\n",panssenger_info->cap_sub_data[kind].sub_type);
		printf("sub_data_len=%d\n",panssenger_info->cap_sub_data[kind].sub_data_len);
		printf("sub_data=%s\n",panssenger_info->cap_sub_data[kind].content_data);	
	}
#endif		
}


void der_data(Panssenger_info * data)
{

#if 1
	unsigned char send_data_cp[1514] = "";
	unsigned char *dest = send_data_cp;
	int data_size = 0;
	Panssenger_info * panssenger_info = data;

	unsigned short h_version = htons(panssenger_info->head_data.version);
	memcpy(dest,&h_version,sizeof(panssenger_info->head_data.version));
	dest += sizeof(panssenger_info->head_data.version);
	data_size += sizeof(panssenger_info->head_data.version);

	memcpy(dest,&panssenger_info->head_data.device_flag,sizeof(panssenger_info->head_data.device_flag));
	dest += sizeof(panssenger_info->head_data.device_flag);
	data_size += sizeof(panssenger_info->head_data.device_flag);

	unsigned short h_data_type = htons(panssenger_info->head_data.data_type);
	memcpy(dest,&h_data_type,sizeof(panssenger_info->head_data.data_type));
	dest += sizeof(panssenger_info->head_data.data_type);
	data_size += sizeof(panssenger_info->head_data.data_type);

	unsigned long h_data_length = htonl(panssenger_info->head_data.data_length);
	memcpy(dest,&h_data_length,sizeof(panssenger_info->head_data.data_length));
	dest += sizeof(panssenger_info->head_data.data_length);
	data_size += sizeof(panssenger_info->head_data.data_length);



	unsigned short h_sub_type = htons(panssenger_info->cap_data.sub_type);
	memcpy(dest,&h_sub_type,sizeof(panssenger_info->cap_data.sub_type));
	dest += sizeof(panssenger_info->cap_data.sub_type);
	data_size += sizeof(panssenger_info->cap_data.sub_type);

	unsigned short c_term_type = htons(panssenger_info->cap_data.term_type);	
	memcpy(dest,&c_term_type,sizeof(panssenger_info->cap_data.term_type));
	dest += sizeof(panssenger_info->cap_data.term_type);
	data_size += sizeof(panssenger_info->cap_data.term_type);

	memcpy(dest,&panssenger_info->cap_data.term_mac,sizeof(panssenger_info->cap_data.term_mac));
	dest += sizeof(panssenger_info->cap_data.term_mac);
	data_size += sizeof(panssenger_info->cap_data.term_mac);

	memcpy(dest,&panssenger_info->cap_data.term_signal,sizeof(panssenger_info->cap_data.term_signal));
	dest += sizeof(panssenger_info->cap_data.term_signal);
	data_size += sizeof(panssenger_info->cap_data.term_signal);

	unsigned long c_cap_time = htonl(panssenger_info->cap_data.cap_time);		
	memcpy(dest,&c_cap_time,sizeof(panssenger_info->cap_data.cap_time));
	dest += sizeof(panssenger_info->cap_data.cap_time);
	data_size += sizeof(panssenger_info->cap_data.cap_time);

#if 1
	int kind = 0;
	for(kind=0;kind <= panssenger_info->sub_data_num;kind++)
	{
		unsigned short s_data_type = htons(panssenger_info->cap_sub_data[kind].sub_type);
		memcpy(dest,&s_data_type,sizeof(panssenger_info->cap_sub_data[kind].sub_type));
		dest += sizeof(panssenger_info->cap_sub_data[kind].sub_type);
		data_size += sizeof(panssenger_info->cap_sub_data[kind].sub_type);


		unsigned short s_data_len = htons(panssenger_info->cap_sub_data[kind].sub_data_len);
		memcpy(dest,&s_data_len,sizeof(panssenger_info->cap_sub_data[kind].sub_data_len));
		dest += sizeof(panssenger_info->cap_sub_data[kind].sub_data_len);
		data_size += sizeof(panssenger_info->cap_sub_data[kind].sub_data_len);


		memcpy(dest,panssenger_info->cap_sub_data[kind].content_data,panssenger_info->cap_sub_data[kind].sub_data_len);
		dest += panssenger_info->cap_sub_data[kind].sub_data_len;
		data_size += panssenger_info->cap_sub_data[kind].sub_data_len;		
	}
#endif
	int i = 0;
	char * cp = send_data_cp;
	char * p = send_data;

	for(i=0;i<data_size;i++)
	{
		*p++ = *cp++^0xbb;
	}
	send_tcp(ip_config,SERVER_DATA_PORT,data_size);
#endif
}

void der_virtual_data(Panssenger_info * data)
{


	unsigned char send_data_cp[1514] = "";
	unsigned char *dest = send_data_cp;
	int i = 0;
	int data_size = 0;
	Panssenger_info *info_manager = data;
	unsigned short h_version = htons(info_manager->head_data.version);
	memcpy(dest,&h_version,sizeof(info_manager->head_data.version));
	dest += sizeof(info_manager->head_data.version);
	data_size += sizeof(info_manager->head_data.version);


	memcpy(dest,&info_manager->head_data.device_flag,sizeof(info_manager->head_data.device_flag));
	dest += sizeof(info_manager->head_data.device_flag);
	data_size += sizeof(info_manager->head_data.device_flag);

	unsigned short h_data_type = htons(info_manager->head_data.data_type);
	memcpy(dest,&h_data_type,sizeof(info_manager->head_data.data_type));
	dest += sizeof(info_manager->head_data.data_type);
	data_size += sizeof(info_manager->head_data.data_type);

	unsigned long h_data_length = htonl(info_manager->head_data.data_length);
	memcpy(dest,&h_data_length,sizeof(info_manager->head_data.data_length));
	dest += sizeof(info_manager->head_data.data_length);
	data_size += sizeof(info_manager->head_data.data_length);

	printf("info_manager->head_data.version = %d\n",info_manager->head_data.version);
	printf("info_manager->head_data.device_flag = %02x:%02x:%02x:%02x:%02x:%02x\n",\
			info_manager->head_data.device_flag[0],info_manager->head_data.device_flag[1],info_manager->head_data.device_flag[2],\
			info_manager->head_data.device_flag[3],info_manager->head_data.device_flag[4],info_manager->head_data.device_flag[5]);
	printf("info_manager->head_data.data_type = %d\n",info_manager->head_data.data_type);
	printf("info_manager->head_data.data_length = %d\n",info_manager->head_data.data_length);

	//printf("cap_sub_data->sub_type=%d\n",cap_sub_data->sub_type);
	char *out = cJSON_Print(info_manager->virtual_info);   //将json形式打印成正常字符串形式  
	printf("%s\n",out);

	strncpy(dest,"{",1);
	dest++;
	char *js_vd = cJSON_Print(info_manager->virtual_info);
	strncpy(dest,js_vd,strlen(js_vd));
	dest+=strlen(js_vd);
	strncpy(dest,"}",1);	

	char * cp = send_data_cp;
	char * p = send_data;
	data_size =  info_manager->head_data.data_length + head_len;

	for(i=0;i<data_size;i++)
	{
		*p++ = *cp++^0xbb;
		//*p++ = *cp++;
	}
	send_tcp(ip_config,SERVER_DATA_PORT,data_size);

}

void AEI_get_lan_macaddr(Panssenger_info *panssenger_info)
{
	//char br_ifname[32] = network_card;
	int fd;
	struct ifreq intf;
	//if (addr == NULL)
	//	return;
	if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("socket error!\n");
		return;
	}
	strcpy(intf.ifr_name, network_card);
	//	printf("network_card=%s\n",network_card);
	if(ioctl(fd, SIOCGIFHWADDR, &intf) != -1)
	{
		//intf.ifr_hwaddr.sa_data
		memcpy(panssenger_info->head_data.device_flag,intf.ifr_hwaddr.sa_data,sizeof(panssenger_info->head_data.device_flag));
	}
	close(fd);
	return;
}
void analysis_pack(unsigned char* recvmsg, int size)
{
#if 1

	char  *delim=";",*pNext = NULL;

	char delim2='=';
	char *s;
	struct recv_mac *pb_cur=NULL; 
	struct recv_mac *pb_prv=NULL; 

	//unsigned char mac_test[6] = {0x88,0x29,0x50,0xde,0xc7,0xef};
	char ap_ssid[32] = "";
	char ap_h_ssid[32] = "";
	char ap_mac[14] = "";
	char ap_capture_time[32] = "";
	char ap_ACCESS_AP_CHANNEL[32] = "";
	char ap_rssi[32] = "";
	char ap_ACCESS_AP_ENCRYPTION_TYPE[32] = "";
	//	char ip_dev[12] = "192.168.1.5" ;
	char tmp_mac[17] = "";//去符号 -
	char term_mac[14] = "";
	char cap_id[32] = "";
	int data_size = 0;
	char virtual_id_tmp[32] = "";
	unsigned short signal = 0;
	if(strlen(recvmsg)<10)
		return ;
	Panssenger_info *panssenger_info = (Panssenger_info *)malloc(sizeof(Panssenger_info));
	panssenger_info->sub_data_num = 0;
	printf("%s\n",recvmsg);
	if(recvmsg[0]==0x31)//ap 
	{
		panssenger_info->data_size = 0;
		panssenger_info->sub_data_num = 0;

		panssenger_info->head_data.version = 1;//文档没有要求 临时要求改为1
		AEI_get_lan_macaddr(panssenger_info);
		panssenger_info->head_data.data_type = 4;  //类型为MAC采集
		panssenger_info->head_data.data_length = 0;

		panssenger_info->cap_data.sub_type = 0;
		panssenger_info->cap_data.term_type = 2;   // 来自AP
		panssenger_info->cap_data.cap_time = time(0);
		s=strtok(recvmsg, delim);
		if(strlen(longde) >= 9)
		{
			fill_sub_info(panssenger_info,LON,strlen(longde),longde);
		}
		if(strlen(latde) >= 9)
		{
			fill_sub_info(panssenger_info,LAT,strlen(latde),latde);
		}
		while((s = strtok(NULL, delim)))
		{	
			if(strstr(s, "ssid") != NULL)
			{
				strcpy(ap_ssid, strchr(s, delim2)+1);
				if(strlen(ap_ssid))
				{
				//	data_size += strlen(ap_ssid);
					fill_sub_info(panssenger_info,COLLECT_AP_SSID,strlen(ap_ssid),ap_ssid);
				}
			}
			else if(strstr(s, "mac") != NULL)
			{
				strcpy(tmp_mac, strchr(s, delim2)+1);
				if(strlen(tmp_mac))
				{
				//	data_size += sizeof(panssenger_info->cap_data.term_mac);
					COPY_STR2MAC(panssenger_info->cap_data.term_mac,tmp_mac);
				}
			}
			else if(strstr(s, "gettime") != NULL)
			{
				//strcpy(passenger_ap->capture_time ,strchr(s, delim2)+1);
			}		
			else if(strstr(s, "chl") != NULL)
			{
				strcpy(ap_ACCESS_AP_CHANNEL ,strchr(s, delim2)+1);
				if(strlen(ap_ACCESS_AP_CHANNEL))
				{
				//	data_size += strlen(ap_ACCESS_AP_CHANNEL);
					fill_sub_info(panssenger_info,COLLECT_AP_CHANNEL,strlen(ap_ACCESS_AP_CHANNEL),ap_ACCESS_AP_CHANNEL);
				}
			}	
			else if(strstr(s, "power") != NULL)
			{
				strcpy(ap_rssi ,strchr(s, delim2)+1);
				if(strlen(ap_rssi))
				{
					signal = htons(atoi(ap_rssi+1));
					memcpy(panssenger_info->cap_data.term_signal,&signal,2);
				//	data_size += sizeof(panssenger_info->cap_data.term_signal);
				}
			}			
			else if(strstr(s, "security") != NULL)
			{
				strcpy(ap_ACCESS_AP_ENCRYPTION_TYPE,strchr(s, delim2)+1);	
				if(strlen(ap_ACCESS_AP_ENCRYPTION_TYPE))
				{	
					fill_sub_info(panssenger_info,COLLECT_AP_ENCRYPT_TYPE,strlen(ap_ACCESS_AP_ENCRYPTION_TYPE),ap_ACCESS_AP_ENCRYPTION_TYPE);
				//	data_size += strlen(ap_ACCESS_AP_ENCRYPTION_TYPE);
				}
			}		

		}
	//	ap_toal++;
		//fill_sub_info(panssenger_info,10,strlen(ip_dev),ip_dev);
		//data_size += strlen(ip_dev);
		//data_size += strlen(UnitCode);
		fill_sub_info(panssenger_info,DEV_ADDR,strlen(UnitCode),UnitCode);
		panssenger_info->data_size += 16;
		panssenger_info->head_data.data_length = panssenger_info->data_size;
		panssenger_info->sub_data_num--;
		print_data(panssenger_info);
		der_data(panssenger_info);
		//send_ap_log(passenger_ap,socket_fd);
	}
	else if(recvmsg[0]==0x32)//sta mac
	{
		panssenger_info->data_size = 0;
		panssenger_info->sub_data_num = 0;

		panssenger_info->head_data.version = 1;
		//panssenger_info->head_data.device_flag   MAC值
		AEI_get_lan_macaddr(panssenger_info);
		//memcpy(panssenger_info->head_data.device_flag,mac_test,sizeof(mac_test));
		panssenger_info->head_data.data_type = 4; //类型为MAC采集	
		panssenger_info->head_data.data_length = 0;//headlen 14
		panssenger_info->cap_data.sub_type = 0;
		panssenger_info->cap_data.term_type = 1;   // 来自STA
		//panssenger_info->cap_data.term_mac
		//panssenger_info->cap_data.term_signal
		panssenger_info->cap_data.cap_time = time(0);// caplen 16
		s=strtok(recvmsg, delim);
		if(strlen(longde) >= 9)
		{
			fill_sub_info(panssenger_info,LON,strlen(longde),longde);
			//data_size += strlen(longde);
		}
		if(strlen(latde) >= 9)
		{
			fill_sub_info(panssenger_info,LAT,strlen(latde),latde);
			//data_size += strlen(latde);
		}
		while((s = strtok(NULL, delim)))
		{

			if(strstr(s, "mac") != NULL){   //sta mac
				strcpy(tmp_mac, strchr(s, delim2)+1);
				if(strlen(tmp_mac))
				{
					COPY_STR2MAC(panssenger_info->cap_data.term_mac,tmp_mac);
					//data_size += sizeof(panssenger_info->cap_data.term_mac);
				}
			}else if(strstr(s, "power") != NULL){
				strcpy(ap_rssi ,strchr(s, delim2)+1);
				if(strlen(ap_rssi))
				{
					signal = htons(atoi(ap_rssi+1));
					memcpy(panssenger_info->cap_data.term_signal,&signal,2);
					//data_size += sizeof(panssenger_info->cap_data.term_signal);
				}
			}else if(strstr(s, "gettime") != NULL){
				//strcpy(passenger_ap->capture_time ,strchr(s, delim2)+1);	
			}else if(strstr(s, "ssidhistroy") != NULL){
				strcpy(ap_h_ssid,strchr(s,delim2)+1);
				if(strstr(ap_h_ssid,","))
				{
					char * p_ssid = strtok(ap_h_ssid,",");
					fill_sub_info(panssenger_info,SSID,strlen(p_ssid),p_ssid);
					//data_size += strlen(p_ssid);
				}
				fill_sub_info(panssenger_info,SSID,strlen(ap_h_ssid),ap_h_ssid);
				//data_size += strlen(ap_h_ssid);
			}
			else if(strstr(s, "apm") != NULL){  //apm
				memset(tmp_mac,0,sizeof(tmp_mac));
				memset(ap_mac,0,sizeof(ap_mac));				
				strcpy(tmp_mac ,strchr(s, delim2)+1);	
				if(strlen(tmp_mac))
				{
					make_mac_del_colon(ap_mac,tmp_mac);	
					fill_sub_info(panssenger_info,COLLECT_AP_MAC,strlen(ap_mac),ap_mac);			
				//	data_size += sizeof(ap_mac);
				}
			}else if(strstr(s, "ssid") != NULL){
				strcpy(ap_ssid, strchr(s, delim2)+1);			
				if(strlen(ap_ssid))
				{
					fill_sub_info(panssenger_info,COLLECT_AP_SSID,strlen(ap_ssid),ap_ssid);
				//	data_size += strlen(ap_ssid);
				}
			}


		}
		fill_sub_info(panssenger_info,DEV_ADDR,strlen(UnitCode),UnitCode);			
		//data_size += strlen(UnitCode);
		//data_size += 16;
		panssenger_info->data_size += 16;
		panssenger_info->head_data.data_length = panssenger_info->data_size;
		panssenger_info->sub_data_num--;

		print_data(panssenger_info);
		der_data(panssenger_info);

	}
#if 1
	else if(recvmsg[0]==0x33)//virtual 
	{

		panssenger_info->head_data.version = 1;
		AEI_get_lan_macaddr(panssenger_info);
		panssenger_info->head_data.data_type = 5; //virtual id
		panssenger_info->head_data.data_length = 0;
		s=strtok(recvmsg, delim);
		panssenger_info->virtual_info=cJSON_CreateObject();
		while((s = strtok(NULL, delim)))
		{	
			if(strstr(s, "type") != NULL){
				strcpy(virtual_id_tmp,strchr(s, delim2)+1);
			}else if(strstr(s, "mac") != NULL){
				memset(tmp_mac,0,sizeof(tmp_mac));
				memset(term_mac,0,sizeof(term_mac));
				strcpy(tmp_mac, strchr(s, delim2)+1);					
				make_mac_del_colon(term_mac,tmp_mac);	

			}else if(strstr(s, "gettime") != NULL){

			}
			else if(strstr(s, "power") != NULL){
				//strcpy(ap_rssi ,strchr(s, delim2)+1);	
				//	printf("ap_rssi = %s\n",ap_rssi);
			}
			else if(strstr(s, "netid") != NULL){
				strcpy(cap_id ,strchr(s, delim2)+1);			
			}
			else if(strstr(s, "apm") != NULL){//apmac
				memset(ap_mac,0,sizeof(ap_mac));
				memset(tmp_mac,0,sizeof(tmp_mac));
				strcpy(tmp_mac, strchr(s, delim2)+1);
				make_mac_del_colon(ap_mac,tmp_mac);
			}else if(strstr(s, "ssid") != NULL){
				strcpy(ap_ssid ,strchr(s, delim2)+1);
			}

		}	
		int cap_time = time(0);	
		//printf("mac mac ===== %s \n",term_mac);
		cJSON_AddStringToObject(panssenger_info->virtual_info,"term_mac",term_mac);  //加入键值，加字符串
		char *virid = get_vitual_type(virtual_id_tmp);  
		if(NULL != virid)
			cJSON_AddStringToObject(panssenger_info->virtual_info,"app_code",virid);  
		cJSON_AddStringToObject(panssenger_info->virtual_info,"internal_id",cap_id); 
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"user_account","289615434");
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"nick_name","289615434");
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"phone","289615434");
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"imsi","101010100000000");
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"imei","101010100000123");
		cJSON_AddStringToObject(panssenger_info->virtual_info,"channel","6");
		cJSON_AddNumberToObject(panssenger_info->virtual_info,"cap_time",cap_time);
		cJSON_AddStringToObject(panssenger_info->virtual_info,"ap_mac",ap_mac);
		//	printf("ap_rssi = %s\n",ap_rssi);
		if(strlen(ap_rssi))
			cJSON_AddStringToObject(panssenger_info->virtual_info,"signal",ap_rssi);
		cJSON_AddNumberToObject(panssenger_info->virtual_info,"crc",0);  //加整数
		cJSON_AddNumberToObject(panssenger_info->virtual_info,"term_type",2);  //加整数
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"history_ssid","chninanet");
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"factory_name","apple");
		cJSON_AddStringToObject(panssenger_info->virtual_info,"collect_ap_ssid",ap_ssid);
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"collect_ap_encrypt_type","03");
		//cJSON_AddStringToObject(panssenger_info->virtual_info,"dev_addr","192.168.2.2");
		cJSON_AddStringToObject(panssenger_info->virtual_info,"dev_addr",UnitCode);

		char *v_data = cJSON_Print(panssenger_info->virtual_info);
		data_size += strlen(v_data);
		data_size += 2;
		panssenger_info->head_data.data_length = data_size;  
		if((NULL!=virid) && (strlen(term_mac)))
		{
			der_virtual_data(panssenger_info);
		}
		cJSON_Delete(panssenger_info->virtual_info);
	}
#endif
#endif
	if(NULL != panssenger_info)
	{
		free(panssenger_info);
		panssenger_info = NULL;
	}
}


void sniffer_data_deal(void *arg)
{
	int deal_index = 0;

	while(1)
	{
		if (packet_need_to_deal == 0)
		{
			pthread_mutex_unlock(&snf_data_arry[deal_index].mutex);
			usleep(1000);
			continue;
		}
		pthread_mutex_lock(&snf_data_arry[deal_index].mutex);
		analysis_pack(snf_data_arry[deal_index].buffer, snf_data_arry[deal_index].data_size);
		packet_need_to_deal--;
		pthread_mutex_unlock(&snf_data_arry[deal_index].mutex);
		deal_index++;
		if (deal_index >= SNF_ARRY_SIZE)
			deal_index = 0;	
		usleep(3000);

	}

}
void start_sniffer_data_deal()
{
	int res = -1;
	pthread_t thread;
	res = pthread_create(&thread, NULL, (void *)sniffer_data_deal, NULL);
	if (res != 0)
	{
		printf("Create thread error\n");
	}
	//pthread_detach(thread);
}

void ReadConf()
{
	FILE *fp;
	int i,n;	
	int kk = 0;
	char s[1500];
	char temp[50];
	char filename[30];
	memset(temp,'\0',sizeof(temp));
	memset(UnitCode,'\0',20);
	memset(CenterIP,'\0',20);
	memset(longde,'\0',12);
	memset(latde,'\0',12);
	memset(network_card,'\0',12);
	//------------------------get config.txt-----------------------------------------	
	char send_data_port[7] = {'\0'};
	char send_data_time_char[10];
	memset(SOURCE,0,3);
	memset(s,'0',sizeof(s));
	strcpy(filename,"/disk/boyi_app/config.txt");
	if (!(fp=fopen(filename,"r")))	
	{
		printf("Error in open file  %s\n",filename);
		exit(1);
	}		
	while(fgets(s,sizeof(s),fp))
	{
		if(strstr(s,"center_ip"))
		{
			memset(temp,0,sizeof(temp));
			get_text_data(s,"\":\"","\"",temp,sizeof(temp));
			memset(CenterIP,0,sizeof(CenterIP));
			kk = hostToIp(temp,CenterIP);
			//if(kk = 1)
			//		exit(1);
		}
		if(strstr(s,"locator_site_code"))
		{
			memset(temp,0,sizeof(temp));
			get_text_data(s,"\":\"","\"",temp,sizeof(temp));
			memset(UnitCode,0,sizeof(UnitCode));
			memcpy(UnitCode,temp,strlen(temp));
		}
		if(strstr(s,"locator_dev_lon"))
		{
			memset(temp,0,sizeof(temp));
			get_text_data(s,"\":\"","\"",temp,sizeof(temp));
			memset(longde,0,sizeof(longde));
			memcpy(longde,temp,strlen(temp));
		}
		if(strstr(s,"locator_dev_lat"))
		{
			memset(temp,0,sizeof(temp));
			get_text_data(s,"\":\"","\"",temp,sizeof(temp));
			memset(latde,0,sizeof(latde));
			memcpy(latde,temp,strlen(temp));
		}
		if(strstr(s,"network_card"))
		{
			memset(temp,0,sizeof(temp));
			get_text_data(s,"\":\"","\"",temp,sizeof(temp));
			memset(network_card,0,sizeof(network_card));
			memcpy(network_card,temp,strlen(temp));
		}

		if(strstr(s,"SERVER_DATA_PORT"))
		{
			memset(send_data_port,0,sizeof(send_data_port));
			get_text_data(s,"\":\"","\"",send_data_port,sizeof(send_data_port));
			SERVER_DATA_PORT =atoi(send_data_port);
		}

	}
	fclose(fp);

}
int main(int argc, char **argv)
{
	pthread_t p_id1;
	int opt_get;
	int  foreground     = 0;



	int sockfd; /* socket descriptors */
	struct sockaddr_in server; /* server's address information */
	struct sockaddr_in client; /* client's address information */
	socklen_t sin_size;
	/* Creating UDP socket */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		/* handle exception */
		perror("Creating socket failed.");
		exit(1);
	}
	bzero(&server,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons(6666);
	server.sin_addr.s_addr = htonl (INADDR_ANY);
	if (bind(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1) {
		/* handle exception */
		perror("Bind error.");
		exit(1);
	} 
	struct timeval tv_out;
	tv_out.tv_sec = 3;//等待1秒
	tv_out.tv_usec = 0;
	setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&tv_out, sizeof(tv_out));
	sin_size=sizeof(struct sockaddr_in);
	time_t tt=0;
	unsigned int packet_index = 0;
	malloc_sniffer_buffer(snf_data_arry, SNF_ARRY_SIZE);
	//signal(SIGINT,sig_teardown);
	//signal(SIGTERM,sig_teardown);

	ReadConf();
	hostToIp(CenterIP,ip_config);
	if(strlen(ip_config) == 0)
	{
		printf("get ip config error\n");
		return 0;
	}
#if 0
	char *separator[] = {" "};     
	char *str = buffer;		 
	char **result = NULL;     
	int n_str = 0;     
	int i = strsplit(&result, &n_str, str, separator, 1, 0, 0); 
#endif
	start_sniffer_data_deal();
	while (1) {

		pthread_mutex_lock(&snf_data_arry[packet_index].mutex);
		memset(snf_data_arry[packet_index].buffer,0 ,SNF_BUF_SIZE);
		snf_data_arry[packet_index].data_size = recvfrom(sockfd, snf_data_arry[packet_index].buffer, SNF_BUF_SIZE - 1, 0,(struct sockaddr *)&client,&sin_size);	
		snf_data_arry[packet_index].cattime = time(NULL);

		if (snf_data_arry[packet_index].data_size <= 0)
		{
			pthread_mutex_unlock(&snf_data_arry[packet_index].mutex);
			continue;
		}
		packet_need_to_deal++;
		pthread_mutex_unlock(&snf_data_arry[packet_index].mutex);
		packet_index++;
		if (packet_index >= SNF_ARRY_SIZE)
			packet_index = 0;
		usleep(100);
	}
	close(sockfd); /* close listenfd */ 
	return 0;
}
