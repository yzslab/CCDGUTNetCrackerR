# CCDGUT Network Cracker - Router version
使用本程序，可解除东莞理工学院城市学院校园网的多客户端检测

注意：此程序仅能在路由器上工作

仅使用KERNEL API，无其它多余的库，可静态编译；USER SPACE程序，非内核模块，无需KERNEL HEADER即可编译（虽然KERNEL SPACE的效率更高，实现更容易，但是嵌入式设备一般拿不到KERNEL HEADER）

仅处理上行且远程端口为80的TCP数据包，不影响下行速率

基于链路层处理数据包，效率高，兼容性好

## 编译方法
直接使用gcc即可：
```
gcc main.c -o CCDGUTNetCrackerR
```
启用调试日志：
```
gcc -DENABLE_LOG main.c -o CCDGUTNetCrackerR
```

## 使用方法
```
CCDGUTNetCrackerR 与内网连接的网络接口名 [daemon] [syslog]
```
例：与内网连接的网络接口名为switch0 (OpenWRT一般是br-lan)：
```
CCDGUTNetCrackerR switch0
```
例：以daemon模式运行（第二个参数只要有值就行，值是什么无所谓）：
```
CCDGUTNetCrackerR switch0 daemon
```
例：使用syslog记录调试信息（仅定义了"ENABLE_LOG"宏才会输出调试信息，调试信息默认输出到stdout）
```
CCDGUTNetCrackerR switch0 syslog
```

## F.A.Q.
### 如何结束程序
给程序发送以下任意一个信号即可：SIGTERM、SIGINT、SIGHUP、SIGQUIT，注意尽量不要使用SIGKILL，这样操作会导致你无法上网：
```
killall -TERM CCDGUTNetCrackerR
```
### 程序退出后，无法访问HTTP网页
一般程序被强制结束或者程序异常退出后会出现这种情况，重新执行一次程序即可，如果不需要程序运行，执行后发送以下任意一个信号结束程序即可恢复：SIGTERM、SIGINT、SIGHUP、SIGQUIT

## 协议
[GNU GENERAL PUBLIC LICENSE Version 3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## 链接
[Zhensheng Yuan's weblog: https://zhensheng.im](https://zhensheng.im)
