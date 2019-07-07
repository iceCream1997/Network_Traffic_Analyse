#include "init.cc"
#include "run.cc"

using namespace std;

int main(int argc,char *argv[]){
    //初始化
    init();
    //抓取时间
    string run_time;
    run_time = argv[1];
    char *end;
    int i = static_cast<int>(strtol(run_time.c_str(),&end,10));
    //过滤规则
    string fileter;
    for(int i = 2; i < argc-1; i++){
        fileter += argv[i];
        fileter += " ";
    }
    fileter += argv[argc-1];
    const char *packet_filter;
    packet_filter = fileter.data();
    //开始运行
    run(packet_filter,i);
    exit(0);
}