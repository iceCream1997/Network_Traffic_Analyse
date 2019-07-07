#pragma once

#include <iostream>
#include <string>
#include "define.h"

using namespace std;

string protocols[PROTOCOL_COUNT] = {"TCP","UDP"};

int creatfile(){
    
    //创建输出文件
    remove(FILENAME);
    FILE *f;
    f = fopen(FILENAME,"w+");
    if(f == NULL){
        perror("\n输出文件创建失败!\n");
        fclose(f);
        return -1;
    }
    fprintf(f, "序号\t\t\t");
    fprintf(f, "确认序号\t\t\t");
    fprintf(f, "标记位\t\t\t\t");
    fprintf(f, "源IP\t\t\t");
    fprintf(f, "目的IP\t\t\t");
    fprintf(f, "源端口\t\t");
    fprintf(f, "目的端口\t\t\t");
    fprintf(f, "协议\t");
    fprintf(f, "数据大小\n");
    
    fclose(f);


    return 0;

}