
# Useing OpenSSL Client certificate

+ CA certificate
+ server and client (using Flask package)

## Create CA certificate
```

# Create a CA (Certificate Authority) [local_ca.ctr]
# Generate Server Certificates        [local_server.key, local_server.crt]
# Generate Client Certificates        [local_client.key, local_client.crt]

bash data/makecert.sh
```
cnf file:
1. CN (Common Name)是憑證名稱，你可以設定任意名稱，設定中文也可以，要以 UTF-8 編碼存檔


## [Validate SSL certificates](https://www.osso.nl/blog/checking-client-ssl-certificate-from-python/ "Title")


```
# change ca.crt path and client.crt path

python valid.py

```

## Local Server and Client

```
python server.py

python client.py
```

it will get 1C309A40488EFB375E7E1F87A8754EB5.jpg image name.

## TODO
 - [用 SAN Certificate 做 Multi-Domain Certificate](https://blog.cssuen.tw/%E7%94%A8-san-certificate-%E5%81%9A-multi-domain-certificate-c7403e05c697 "Title")

 - [使用OpenSSL生成带有SubjectAltName的自签名证书](https://blog.csdn.net/u010983881/article/details/83619603 "Title")

- [OpenSSL 生成「自签名」证书遇到的 missing_subjectAltName 问题](https://moxo.io/blog/2017/08/01/problem-missing-subjectaltname-while-makeing-self-signed-cert/ "Title")

## Reference

1. [Flask 配置 HTTPS 網站 SSL 安全認證](https://medium.com/@charming_rust_oyster_221/flask-%E9%85%8D%E7%BD%AE-https-%E7%B6%B2%E7%AB%99-ssl-%E5%AE%89%E5%85%A8%E8%AA%8D%E8%AD%89-36dfeb609fa8 "Title")

2. [如何使用 OpenSSL 建立開發測試用途的自簽憑證 (Self-Signed Certificate)](https://blog.miniasp.com/post/2019/02/25/Creating-Self-signed-Certificate-using-OpenSSL "Title")

3. [如何使用 OpenSSL 建立開發測試用途的自簽憑證 (Self-Signed Certificate)](https://blog.miniasp.com/post/2019/02/25/Creating-Self-signed-Certificate-using-OpenSSL "Title")

4. [python关于SSL/TLS认证的实现](https://blog.csdn.net/vip97yigang/article/details/84721027 "Title")

5. [SSL/TLS协商过程详解](https://blog.csdn.net/zhangtaoym/article/details/55259889 "Title")

6. [【网络安全】在局域网里创建个人CA证书](https://blog.csdn.net/yannanxiu/article/details/70670225 "Title")

7. [Create a self-signed certificate using OpenSSL](https://blog.cssuen.tw/create-a-self-signed-certificate-using-openssl-240c7b0579d3 "Title")

8. [SSL/TLS client certificate verification with Python v3.4+ SSLContext](https://www.electricmonk.nl/log/2018/06/02/ssl-tls-client-certificate-verification-with-python-v3-4-sslcontext/ "Title")

9. [Doing SSL client authentication is python
](https://stackoverflow.com/questions/33504746/doing-ssl-client-authentication-is-python "Title")

10. <https://unix.stackexchange.com/questions/288517/how-to-make-self-signed-certificate-for-localhost>

11. <https://tech-habit.info/posts/https-cert-based-auth-with-flask-and-gunicorn/>

12. [Root CA configuration file](https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html "Title")

13. [How to create a CSR with OpenSSL](https://www.switch.ch/pki/manage/request/csr-openssl/ "Title")

14. [How to setup your own CA with OpenSSL](https://gist.github.com/lancejpollard/c46ee524457970e0f692d290c4f625b9 "Title")

