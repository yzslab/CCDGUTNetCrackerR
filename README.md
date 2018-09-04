# CCDGUT Network Cracker - Router version
使用本程序，可解除东莞理工学院城市学院校园网的多客户端检测

注意：仅能在路由器上工作

仅使用KERNEL API，无其它多余的库，可静态编译

仅处理上行且远程端口为80的TCP数据包，不影响下行速率

## 编译方法
直接使用gcc即可：
```
gcc main.c -o CCDGUTNetCrackerR
```
启用调试日志：
```
gcc -DENABLE_LOG -o CCDGUTNetCrackerR
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
## 协议
[GNU GENERAL PUBLIC LICENSE Version 3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## 链接
[Zhensheng Yuan's weblog: https://zhensheng.im](https://zhensheng.im)
