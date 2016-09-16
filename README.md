# Network-Sniffer
网络嗅探器
#开发环境：Linux，C，vim，gcc，Makefile
#项目简介：捕获程序开启的网络连接，并在日志文件打印相应的信息供用户查看

#项目描述：
1. 创建日志文件和原始套接字侦听负载为IP数据报的以太网帧
2. select循环检测是套接字还是标准输入，如果是套接字则读取以太网帧内容
3. 解析以太网帧内容，获取IP头部，并判断IP负载类型
4. 将IP头部信息，以及IP负载的头部信息和用户数据写入日志文件中
5. 编写脚本文件实现一个简易的控制台，包括构建工程，运行工程和清理工程
