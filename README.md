# CCDGUT Network Cracker - Router version
使用本程序，可解除东莞理工学院城市学院校园网的多客户端检测

注意：此程序仅能在使用Linux Kernel的路由器（例如OpenWRT）上工作

仅使用KERNEL API，无其它多余的库，可静态编译；USER SPACE程序，非内核模块，无需KERNEL HEADER即可编译（虽然KERNEL SPACE的效率更高，实现更容易，但是嵌入式设备一般拿不到KERNEL HEADER）

仅处理上行且远程端口为80的TCP数据包，不影响下行速率

基于链路层处理数据包，效率高，兼容性好

**使用后，若觉得效果不错，欢迎点击右上角的"★ Star" (#^.^#)**

## 开始使用

### 获取程序
获取程序有两种途径，一种是直接获取已预先编译好的Release版本，另一只是获取源码自行编译。
#### 途径一：使用Release版本
使用mipsel架构的路由器比较多，因此Release版目前仅提供mipsel架构的二进制可执行文件。

一般都可以直接使用CDGUTNetCrackerR-mipsel-static，如无法使用，请下载toolchain自行编译。
##### 以OpenWRT为例
下面的命令将下载最新的Release版程序并存放到/usr/sbin/CCDGUTNetCrackerR：
```
# 注意这里的下载地址并不是HTTPS的，而且不是从GITHUB的Release服务器下载的。
# 因为OpenWRT自带的wget不支持HTTPS，Amazon S3国内也不好访问。
# 注重安全的下载后请验证MD5值：https://ccdgut-net-cracker.yuninter.net/latest/md5sum.txt
# 如果你安装了支持https的wget/curl以及CA证书，可自行把http替换为https。
wget -O- http://ccdgut-net-cracker.yuninter.net/latest/CCDGUTNetCrackerR-mipsel-static > /usr/sbin/CCDGUTNetCrackerR
md5sum /usr/sbin/CCDGUTNetCrackerR # v0.1.3-alpha的CCDGUTNetCrackerR-mipsel-staticMD5值为cf618dadcfdd94adc145ba8c2b2a21a3  
chmod +x /usr/sbin/CCDGUTNetCrackerR
```

#### 途径二：获取源码自行编译
下载toolchain，直接使用gcc即可（注意把gcc替换成你的toolchain的gcc的路径）：
```
gcc main.c -o CCDGUTNetCrackerR
```
启用调试日志：
```
gcc -DENABLE_LOG main.c -o CCDGUTNetCrackerR
```

### 使用方法
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
CCDGUTNetCrackerR switch0 daemon syslog
```

### 设置程序开机自启动
把程序的执行命令加入到/etc/rc.local即可。

首先删除/etc/rc.local中已有的且与本程序相关的启动命令：
```
sed -i "/CCDGUTNetCrackerR/d" /etc/rc.local
```
查看/etc/rc.local有没有exit 0
```
cat /etc/rc.local | grep "exit 0"
```
如果有输出exit 0，则执行（注意把br-lan替换为路由器连接内网的网络接口名）：
```
sed -i "/exit 0/i/usr/sbin/CCDGUTNetCrackerR br-lan daemon" /etc/rc.local
```
否则（注意把br-lan替换为路由器连接内网的网络接口名）：
```
echo /usr/sbin/CCDGUTNetCrackerR br-lan daemon >> /etc/rc.local
```


## F.A.Q.
### 如何结束程序
给程序发送以下任意一个信号即可：SIGTERM、SIGINT、SIGHUP、SIGQUIT，注意尽量不要使用SIGKILL，这样操作会导致你无法上网：
```
killall -TERM CCDGUTNetCrackerR
```
### 程序退出后，无法访问HTTP网页
一般程序被强制结束或者程序异常退出后会出现这种情况，重新执行一次程序即可，如果不需要程序运行，执行后发送以下任意一个信号结束程序即可恢复：SIGTERM、SIGINT、SIGHUP、SIGQUIT

## 相关项目
城院校园网账号自动认证：[CCDGUTNetAuth](https://github.com/yzsme/CCDGUTNetAuth)
中兴&天翼自动认证(虽然现在不需要中兴认证了，但是天翼认证部分还能正常使用)：[zte-client](https://github.com/yzsme/zte-client)

## 协议
[GNU GENERAL PUBLIC LICENSE Version 3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## 链接
[Zhensheng Yuan's weblog: https://zhensheng.im](https://zhensheng.im)
