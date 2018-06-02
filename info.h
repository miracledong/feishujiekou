/* ************************************************************************
 *       Filename:  info.h
 *    Description:  
 *        Version:  1.0
 *        Created:  2018年01月28日 19时44分56秒
 *       Revision:  none
 *       Compiler:  gcc
 *         Author:  YOUR NAME (), 
 *        Company:  
 * ************************************************************************/
#include "list.h"
#include "cJSON.h"
#define MAX_JSON_NUM	10
#define MAX_SUB_DATA_NUM	10

enum SUB_DATA_TYPE
{
	LON = 1,LAT,SSID,HIS_CTIME,CRC,COLLECT_AP_SSID,COLLECT_AP_MAC,COLLECT_AP_CHANNEL,COLLECT_AP_ENCRYPT_TYPE,DEV_ADDR
};
typedef struct _cap_sub_data
{
    unsigned short sub_type;
	unsigned short sub_data_len;
	unsigned char *content_data;
}Cap_sub_data;
	//以xia为必填参数，以shang为可选参数
typedef struct _cap_data
{
	unsigned short sub_type;//MAC数据类型： 0：MAC数据
	unsigned short term_type;//0：表示未能识别终端类型，1：无线帧来自STA，2：无线帧来自AP ,3: 无线帧来自TAG.
    unsigned char term_mac[6];
    unsigned char term_signal[2];
	unsigned long cap_time; //时间戳
}Cap_data;

typedef struct _head_data
{
	unsigned short version;       //协议版本号
	unsigned char  device_flag[6]; //探针MAC
    unsigned short data_type;   //03：TAG采集 04：MAC采集 05：虚拟身份采集
	unsigned long data_length; //数据域长度 N
}Head_data;



#if 0
typedef struct _info_unit
{
	unsigned long length;
	unsigned char code[2];
	char *data;
}Info_unit;

//以下为4g数据通道
typedef struct _4g_pro_data
{
	unsigned long length;       //长度：4个字节，其值为包括长度字段在内的所有字段之和
	unsigned char version;      //版本号：1个字节，版本号必须为2
	unsigned char device_num[4];   //设备编号：4个字节，设备MAC后4个字节
	unsigned char order_num[2];    //序号：主动发起方填写，应答方原样返回
	unsigned char reserve[2];
	unsigned char cmd_num;      //命令编码：1字节,0x13,上报4G数据,0x18上报经纬度
	unsigned char ack_flag;     //应答标志，1个字节，必须为0
	Info_unit *command_sys;    //命令体：由一个或多个信息单元组成
}Pro_4g_data;
#endif

#if 0
typedef struct _info_manager 
{
	struct list_head head;
	cJSON *js_arr[MAX_JSON_NUM];
	Head_data head_data;
	int js_num;
}Info_manager;

typedef struct _cap_manager 
{
	struct list_head head;
	Head_data head_data;
	Cap_data cap_data;
	Cap_sub_data cap_sub_data[MAX_SUB_DATA_NUM];
	int sub_data_num;
}Cap_manager;
#endif

typedef struct _passigner_info
{
	Head_data head_data;
	cJSON *virtual_info;
	Cap_data cap_data;
	Cap_sub_data cap_sub_data[MAX_SUB_DATA_NUM];
	int sub_data_num;
	int data_size;
}Panssenger_info; 






struct sniffer_data
{
   unsigned char *buffer;
   int data_size; // recv data size
   time_t cattime;
   int type;
   pthread_mutex_t mutex;
};
