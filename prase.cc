#pragma once
#include "define.h"
#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <fstream>
#include <iostream>
#include "struct.h"

using namespace std;

typedef struct _argument{
    pcap_t *handle;
    HASH_TABLE *wr;
}argument;


//抓取到的第一个包的时间
time_t first_catch_time;
//抓取到的最后一个包的时间
time_t last_catch_time;

//数据报解析函数
void parse(const u_char *packet_data, char *catch_time, int packet_size,int out_id);

//解析HTTP
int parseHTTP(char *tcp_packet, int tcp_data_len, int tcp_head_len);

//固定格式写入数据包记录文件
void writeFile(unsigned int sequence, unsigned int ack,
               char *flag_str, char *src_ip, char *dest_ip,
               unsigned short src_port, unsigned short dest_port,
               char *pro_name, unsigned int data_len);

//固定格式写入流量分析文件
void writeFlowFile(char *catch_time, char *src_ip, char *dest_ip,
                   unsigned short src_port, unsigned short dest_port,
                   unsigned int packet_len, char *pro_name);


/* 包捕获处理函数
   最后一个参数指向一块内存空间，这个空间中存放的就是pcap_loop抓到的数据包
   第二个参数结构体是由pcap_loop自己填充的，用来取得一些关于数据包的信息 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                  const u_char *packet_data){
    struct tm _tm;
    char time[20];
    time_t local_tv_sec;
    static int id = 0;


    //将时间戳转换成可识别的格式
    local_tv_sec = header->ts.tv_sec;
    _tm = *localtime(&local_tv_sec);
    sprintf(time, "%4.4d.%2.2d.%2.2d-%2.2d:%2.2d:%2.2d",
        _tm.tm_year+1900, _tm.tm_mon + 1, _tm.tm_mday,
        _tm.tm_hour, _tm.tm_min, _tm.tm_sec );

    //记录抓包时间
    if(id == 0){
        first_catch_time = local_tv_sec;
    }
    last_catch_time = local_tv_sec;



    ETHERNET_HEADER *ether;
    ether = (ETHERNET_HEADER *)(packet_data);


    /* 数据包解析 */
    parse(packet_data, time, header->len,id);

}


/* 解析数据包 */
void parse(const u_char *packet_data, char *catch_time, int packet_size,int out_id){
/* 获得IP数据包头部 */
    IP_HEADER *ip;
    unsigned int protocol;
    unsigned int ip_head_len;
    unsigned int ip_total_len;

    //以太网头部占14字节
    ip = (IP_HEADER *)(packet_data + 14);
    //数据包协议
    protocol = *((unsigned int *)(&ip->protocol)) & 0xff;
    //IP头部长度
    ip_head_len = (ip->version_headLength & 0xf)*4;
    //IP总长度
    ip_total_len = ntohs(ip->total_length);
    //数据包长度
    unsigned int packet_len = ip_total_len - ip_head_len;
    //源IP
    char src_ip[50];
    sprintf(src_ip, "%d.%d.%d.%d",
            ip->src_ip_address.byte1,
            ip->src_ip_address.byte2,
            ip->src_ip_address.byte3,
            ip->src_ip_address.byte4);
    //目的IP
    char dest_ip[50];
    sprintf(dest_ip, "%d.%d.%d.%d",
            ip->dest_ip_address.byte1,
            ip->dest_ip_address.byte2,
            ip->dest_ip_address.byte3,
            ip->dest_ip_address.byte4);

    unsigned short src_port, dest_port;
    unsigned int ack = 0;
    unsigned int sequence = 0;
    unsigned short flag;
    //数据长度
    unsigned int data_len;
    char flag_str[100];
    char pro_name[5];
    string stat = " ";

    int index;
    if(protocol == IP_TCP){             //TCP协议报头
        /* 获得TCP首部 */
        TCP_HEADER *tcp;
        tcp = (TCP_HEADER *)((unsigned char *)ip + ip_head_len);

        //从网络字节顺序(大端)转换为主机字节顺序（小端）
        //大端模式：最高位放低地址
        //小端模式：最低位放低地址
        src_port = ntohs(tcp->src_port);
        dest_port = ntohs(tcp->dest_port);
        ack = ntohl(tcp->ack);
        sequence = ntohl(tcp->sequence);
        //TCP首部长度
        unsigned short hrf = ntohs(tcp->headlen_retain_flag);
        unsigned int tcp_head_len = ((hrf & 0xf000) >> 12)*4;
        //TCP数据长度
        data_len = packet_len - tcp_head_len;
        //标记
        flag = hrf & 0x3f;

        strcpy(flag_str, "");
        if((flag & TH_ACK) == TH_ACK){
            strcat(flag_str, "ACK=1 ");
            stat = "ESTABLISHEN";
            
        }else{
            strcat(flag_str, "ACK=0 ");
        }

        if((flag & TH_SYN) == TH_SYN){
            strcat(flag_str, "SYN=1 ");
            stat = "SYN_SENT";
        }else{
            strcat(flag_str, "SYN=0 ");
        }

        if((flag & TH_FIN) == TH_FIN){
            strcat(flag_str, "FIN=1");
            stat = "CLOSEING";
        }else{
            strcat(flag_str, "FIN=0");
        }

        strcpy(pro_name, "TCP");

        writeFlowFile(catch_time, src_ip, dest_ip, src_port,
                  dest_port, packet_len, pro_name);

    }else if(protocol == IP_UDP){                //UDP协议报头
        /* 获得UDP首部 */
        UDP_HEADER *udp;
        udp = (UDP_HEADER *)((unsigned char *)ip + ip_head_len);

        //从网络字节顺序转换为主机字节顺序
        unsigned short tcp_head_len;
        src_port = ntohs(udp->src_port);
        dest_port = ntohs(udp->dest_port);
        tcp_head_len = ntohs(udp->length);
        data_len = packet_len - tcp_head_len;

        strcpy(flag_str, "\t\t");
        ack = 0;
        sequence = 0;
        strcpy(pro_name, "UDP");

        writeFlowFile(catch_time, src_ip, dest_ip, src_port,
                  dest_port, packet_len, pro_name);

    }else{
        // TODO 其它协议
        return;
    }

    writeFile(sequence, ack, flag_str, src_ip, dest_ip,
              src_port, dest_port, pro_name, data_len);
 
    //printf("%d\t%s\t%d\t", out_id, time, packet_size);
    // printf("%s\t%d\t%s\t  %d.%d.%d.%d -> %d.%d.%d.%d\t%d\t%d\t\t",catch_time, packet_size,pro_name,
    //         ip->src_ip_address.byte1,
    //         ip->src_ip_address.byte2,
    //         ip->src_ip_address.byte3,
    //         ip->src_ip_address.byte4,
    //         ip->dest_ip_address.byte1,
    //         ip->dest_ip_address.byte2,
    //         ip->dest_ip_address.byte3,
    //         ip->dest_ip_address.byte4,
    //         src_port,
    //         dest_port,
    //         stat);
    // cout<<stat<<endl;

    HASH_NODE temp;
    temp.catch_time = catch_time;
    temp.packet_len = packet_size;
    temp.name = pro_name;
    temp.src_ip_addr = src_ip;
    temp.dest_ip_addr = dest_ip;
    temp.src_port = src_port;
    temp.dest_port = dest_port;
    temp.stat = stat;

    ma.lock();

    data_hash.table.push_back(temp);
    if(temp.name == "TCP")
        data_hash.tcpnum++;
    if(temp.name == "UDP")
        data_hash.udpnum++;
    
    data_hash.packetnum++;
    data_hash.datasize += temp.packet_len;

    ma.unlock();
    
    
}



/* 固定格式写入数据包记录文件 */
void writeFile(unsigned int sequence, unsigned int ack,
               char *flag_str, char *src_ip, char *dest_ip,
               unsigned short src_port, unsigned short dest_port,
               char *pro_name, unsigned int data_len){
    FILE *f;
    f = fopen(FILENAME, "a+");
    if(f == NULL){
        printf("\n该数据包写入文件失败\n");
    }else{
        char buffer[50];
        //序号
        sprintf(buffer, "%-16u", sequence);
        fprintf(f, buffer);
        //确认序号
        sprintf(buffer, "%-16u", ack);
        fprintf(f, buffer);
        //标记位
        sprintf(buffer, "%s\t", flag_str);
        fprintf(f, buffer);
        //源IP
        fprintf(f, src_ip);
        fprintf(f, "\t");
        //目的IP
        fprintf(f, dest_ip);
        fprintf(f, "\t\t");
        //源端口
        sprintf(buffer, "%d\t\t",src_port);
        fprintf(f, buffer);
        //目的端口
        sprintf(buffer, "%d\t\t",dest_port);
        fprintf(f, buffer);
        //协议
        fprintf(f, pro_name);
        fprintf(f, "\t");
        //数据包大小
        sprintf(buffer, "%d", data_len);
        fprintf(f, buffer);
        fprintf(f, "\n");
    }
    fclose(f);
}

/* 固定格式写入流量分析文件 */
void writeFlowFile(char *catch_time, char *src_ip, char *dest_ip,
                   unsigned short src_port, unsigned short dest_port,
                   unsigned int packet_len, char *pro_name){
    /* 抓取时间@源IP@目的IP@源端口@目的端口@数据包长度 */

    string buf;
    string file_node;
    file_node = catch_time;
    file_node += "@";
    file_node += src_ip;
    file_node += "@";
    file_node += dest_ip;
    file_node += "@";
    file_node += to_string(src_port);
    file_node += "@";
    file_node += to_string(dest_port);
    file_node += "@";
    file_node += to_string(packet_len);
    file_node += "\n";


    //写入文件
    string flowname;
    flowname += pro_name;
    flowname += ".txt";
    ofstream	OsWrite(flowname,ofstream::app);
    OsWrite<<file_node;
    OsWrite<<endl;
    OsWrite.close();


}