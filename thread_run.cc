#pragma once
#include <pthread.h>
#include <time.h>
#include <pcap.h>
#include <iostream>
#include <unistd.h>
#include <thread>

using namespace std;

typedef struct _argument{
    pcap_t *handle;
    int timeLen;
}argument;

/* 子线程运行函数 */
void thread_clock(argument *argv){
    //使自身变成非阻塞线程
    cout<<"1"<<endl;
    pthread_detach(pthread_self());
    
    pcap_t *handle = ((argument*)argv)->handle;
    int timeLen = ((argument*)argv)->timeLen;
    //单位是毫秒
    sleep(timeLen*1000);
    //停止抓包
    pcap_breakloop(handle);
}

void thread_run(pcap_t *devHandler,pcap_if_t *dev){
    pthread_t clock_thread = 105;
    argument arg;
    int argv_time;

    printf("输入抓取时间(秒):");
    scanf("%d", &argv_time);
    arg.timeLen = (argv_time > 0) ? argv_time : 60;
    arg.handle = devHandler;
    printf("抓取时长：%d s\n", arg.timeLen);
    //argument结构体传入
    thread* t = new thread(thread_clock,&arg);
    if(t == NULL){
        perror("pthread_create");
        exit(1);
    }

    printf("\n正在监听:%s...\n", dev->description);
}

