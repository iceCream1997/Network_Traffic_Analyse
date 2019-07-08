#pragma once
#include <iostream>
#include <cstdio>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <thread>
#include "prase.cc"
#include <mutex>

using namespace std;

char *local_ip;

bool flag = false;

/* 子线程运行函数 */
void write_hash(argument *argv){

    //使自身变成非阻塞线程
    pthread_detach(pthread_self());
    
    pcap_t *handle = argv->handle;


    pcap_loop(handle, -1, packet_handler, NULL);


}

void read_hash(argument *argv){
    //使自身变成非阻塞线程
    pthread_detach(pthread_self());
    printf("\ttime\t\tlength\t协议类型\t源IP\t\t目的IP\t\t源端口\t目的端口\tstat\n");
    while(1){
        if(flag)
            break;
        ma.lock();
        if(!data_hash.table.empty()){
            HASH_NODE ou = data_hash.table.front();
            cout<<ou.catch_time<<"\t"
                <<ou.packet_len<<"\t"
                <<ou.name<<"\t\t"
                <<ou.src_ip_addr<<"\t"
                <<ou.dest_ip_addr<<"\t"
                <<ou.src_port<<"\t"
                <<ou.dest_port<<"\t\t"
                <<ou.stat<<endl;
            data_hash.table.pop_front();
        }
        ma.unlock();
        
    }


}

void run(const char packet_filter[50],int run_time){
    pcap_if_t *alldevs;
    pcap_t *devHandler;
    //错误信息缓冲区
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device;
    //获取网卡设备
    if(pcap_findalldevs(&alldevs, error_buffer) == -1){
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", error_buffer);
        exit(1);
    }

    //打印列表
   // cout<<"网络适配器列表:"<<endl;
    pcap_if_t *dev;
    // int i = 0;
    // for(dev = alldevs; dev; dev = dev->next){
    //    printf("%d.\t%s\n", ++i, dev->name);
    //     if(dev->description){
    //         printf("\t(%s)\n\n",dev->description);
    //     }
    //     else{
    //         printf("\t(No description available)\n\n");
    //     }
    // }

    // if(i == 0){
    //     printf("\n错误：未发现设备!!!\n");
    //     exit(1);
    // }

    // int num;
    // printf("选择设备号（1-%d）:",i);
    // scanf("%d",&num);
    // getchar();
    // if(num < 1 || num > i){
    //     printf("输入范围错误\n");
    //     //释放设备列表
    //     pcap_freealldevs(alldevs);
    //     exit(1);
    // }

    /* 跳转到选中的适配器 */
    //for(dev = alldevs, i=0; i < num-1 ;dev = dev->next, i++);
    dev = alldevs;
    //dev = dev->next;
    /* 获得本地IP */
    struct pcap_addr *addr = dev->addresses;
    struct sockaddr_in *sin;
    for(;addr;addr = addr->next){
        sin = (struct sockaddr_in *)addr->addr;
        if(sin->sin_family = AF_INET){
            local_ip = inet_ntoa(sin->sin_addr);
        }
    }

    /* 打开设备 */
    if ((devHandler = pcap_open_live(dev->name,
                                65536,    // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                0,      //网卡进入混杂模式
                                1000,   // 读取超时时间
                                error_buffer)) == NULL){
        fprintf(stderr,"\n适配器打开失败,不支持%s\n", dev->name);
        cout<<error_buffer<<endl;
        //释放设备列表
        pcap_freealldevs(alldevs);
        exit(1);
    }

    /* 检查数据链路层，只考虑以太网 */
    if(pcap_datalink(devHandler) != DLT_EN10MB){
        fprintf(stderr,"\n该程序只分析以太网数据帧,该设备不支持,请重选设备\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }

    //网络号与掩码
    bpf_u_int32 net, mask;
    //获得网卡的网络号与掩码
    pcap_lookupnet(dev->name, &net, &mask, error_buffer);

    struct bpf_program fcode;
    //char packet_filter[] = "ip or tcp or udp";  //ether要MAC地址
    
    /* 编译过滤规则 */
    //将第三个参数指定的字符串编译到过滤程序中
    //第四个参数控制结果代码的优化
    //最后一个参数指定本地网络的网络掩码
    //这一步给fcode赋值
    if (pcap_compile(devHandler, &fcode, packet_filter, 1, mask) < 0){
        printf("\n过滤规则编译失败\n");
        exit(1);
    }
    /* 设置过滤规则 */
    if (pcap_setfilter(devHandler, &fcode) < 0){
        printf("\n过滤规则设置失败\n");
        exit(1);
    }

    pthread_t clock_thread = 105;
    argument arg;
    int argv_time;

    arg.handle = devHandler;
    printf("抓取时长：%d s\n", run_time);
    //argument结构体传入
    
    //printf("\n正在监听:%s...\n", dev->description);

    /* 释放设备列表 */
    pcap_freealldevs(alldevs);
    HASH_TABLE info;

    arg.wr = &info;
    thread write_thread(write_hash,&arg);
    // if(write_thread){
    //     perror("pthread_create");
    //     exit(1);
    // }

    thread* read_thread = new thread(read_hash,&arg);

    sleep(run_time);
    /* 关闭处理 */
    pcap_close(devHandler);

    ma.lock();
    flag = true;
    ma.unlock();

    printf("\n\t\t---抓取结束---\n\n");
    printf("结果:\n");
    printf("总数据包数目:%d,其中TCP数据包%d个，UDP数据包%d个！\n",data_hash.packetnum,data_hash.tcpnum,data_hash.udpnum);
    printf("总数据大小:%d\n",data_hash.datasize);           
}
    
