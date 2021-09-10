使用CysecSDK适配LibCurl 使用说明

1 demo1.c SSL双向认证调用反向接口的libcurl SSL相关设置说明，示例代码（客户端验证证书链，证书状态，证书主题项）。
2 demo1_1.c SSL双向认证，使用证书文件路径方式。
3 demo1_2.c SSL双向认证使用回调函数性能测试，执行多次perform,并打印每一次消耗的时间.
4 demo1_3.c SSL双向认证多线程调用
5 demo1_4.c SSL双向认证多线程、使用multi接口调用
6 demo2.c SSL单项认证调用反向接口的libcurl SSL相关设置说明，示例代码 （客户端验证证书链，证书状态，证书主题项）。
7 demo2_1.c SSL单项认证使用证书文件单向连接SSL服务器。
8 demo2_2.c SSL单项认证使用反向回调测试单向认证，执行多次perform,并打印每一次消耗的时间
9 demo3.c 为SSL单项认证libcurl SSL相关设置说明，示例代码 （客户端不验证证书链，证书状态，证书主题项）
10 demo5.c 为通过SSL单向认证。向SCEP服务器注册证书。
11 demo6.c 为了对OCSP Stapling 有效性做宽限测试。
12 vpk_scep.c 私钥扩展接口的SCEP发证demo