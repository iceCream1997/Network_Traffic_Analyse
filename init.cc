#pragma once
#include "File.cc"

using namespace std;

void init(){
    if(creatfile() == -1){
        perror("/ncreatfile()创建文件失败!");
        exit(1);
    }   
}