# dns_capture
适用于dns服务器的dns抓包程序

# 安装libpcap

yum install libpcap

# 运行命令

sudo ./dns_capture_linux_amd64 -d www.baidu.com -i eth0

```console
Usage of ./dns_capture_linux_amd64:
  -d string
    	指定dns解析的域名
  -i string
    	指定捕获数据包的网口 (default "eth0")
  -o string
    	指定输出的文件名
  -w int
    	指定抓取数据包数量 (default -1)
```
