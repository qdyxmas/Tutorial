#encoding=utf-8
import requests
import time,os,re
from requests_toolbelt.adapters import source

responses = []
s = requests.Session()

class PotalAuth():
    def __init__(self,**kargs):
        #kargs 必须时IP与域名的字典形式kargs={"192.168.3.33":"http://www.baidu.com","192.168.3.34":"http://www.qq.com"}
        #[(ip,url,header)]
        # threading.Thread.__init__(self)
        self.get_list={}    #存放最初重定向的IP与对应的域名,用于最后时刻认证通过后的判断条件
        self.get_response={} ;#存放get请求的响应
        self.get_result = {} ;#存放请求的结果Pass或者Fail
        self.get_pass={} ;#判断某个IP对应的请求是否正常
        self.post_list={} #主要用于存放发送认证信息后的结果值
        self.post_response={} #主要用于存放发送认证信息后响应值
        self.post_result={} #主要用于存放发送认证信息后的是否认证成功
        self.header=[]
        self.all_result={} #总的结果保存值 {IP:[域名,第一次域名,结果1,第二次域名,结果2,密码]}
        self.filename="./testresult.csv"
        self.parser(**kargs)
        #初始化配置IP地址
    def parser(self,**kargs):
        for key,value in kargs.items():
            self.get_list[key]=value
            self.all_result[key]=[]
            self.all_result[key].append(value)
    def config_macvlan(self):
        macvlan_dict={}
        i=1
        for key in self.get_list.keys():
            #得到所有的IP地址,把IP地址转换成点分十进制得到Mac地址
            mac="00:11:"+":".join(map(lambda z: "%02x" %(int(z)),key.split(".")))
            macvlan_dict[key]=[i,mac]
            i=i+1
        gw=re.sub(r"([0-9]+$)","1",key)
        cmdList=["yes|cp /etc/iproute2/rt_tables /etc/iproute2/rt_tables.bak"]
        # print "macvlan_dict=",macvlan_dict
        for k,v in macvlan_dict.items():
            cmdList.append("ip link add link eth1 veth%d address %s type macvlan" %(v[0],v[1]))
            cmdList.append("ifconfig veth%d %s/24 up" %(v[0],k))
            cmdList.append("ip rule add from %s/32 table %d" %(k,v[0]))
            cmdList.append("ip route replace default via %s dev veth%d src %s table %s" %(gw,v[0],k,v[0]))
            cmdList.append("""echo "%d %d">>/etc/iproute2/rt_tables""" %(v[0],v[0]))
        for cmd in cmdList:
            print "cmd=",cmd
            os.system(cmd)
    def del_macvlan(self):
        #第一步得到所有的接口vethN和ip地址ifconfig  -a|grep -A 1 veth*
        cmd="""ifconfig  -a|grep -A 1 veth*"""
        retlines=os.popen(cmd).readlines()
        for i in retlines:
            veth_iface=re.search(r"(veth[0-9]+)",i)
            if veth_iface:
                cmd="ip link del link eth1 name %s dev %s" %(veth_iface.group(),veth_iface.group())
            veth_ip=re.search(r"([0-9]+.){3}([0-9]+)",i)
            if veth_ip:
                cmd=" ip rule del from %s" %(veth_ip.group())
            print "cmd=",cmd
            os.system(cmd)
        #还原配置文件/etc/iproute2/rt_tables
        cmd="yes|cp /etc/iproute2/rt_tables.bak /etc/iproute2/rt_tables"
        os.system(cmd)
    def geturl(self,**kargs):
        #请求域名重定向到认证页面则认为通过
        header={}
        #根据kargs形成三元组
        getlist=[]
        for key,value in kargs.items():
            getlist.append([key,value,header,{}])
        #开始记录时间
        now=time.time()
        self.send_packet("get",*getlist)
        #判断返回结果
        for i in getlist:
            self.post_list[i[0]]=self.get_response[i[0]].url
            # if self.get_response[i[0]].url.startswitch == "http://192.168.244.244":
                # 如果前缀为该域名则保存起来,形成新的ip-url-header组
            if  self.post_list[i[0]].startswith("http://192.168.244.244"):
                self.get_result[i[0]] = "Pass"
            else:
                self.get_result[i[0]] = "Fail"
            self.all_result[i[0]].append(self.get_response[i[0]].url)
            self.all_result[i[0]].append(self.get_result[i[0]])
        #调用写入学习参数对结果进行保存
        
    def portal(self,**kargs):
        #把用户名密码与对应的IP地址组成新的请求,进行认证
        #最后到达页面为认证通过后指定页面则认为通过
        header={'Host': '192.168.244.244',
                'Accept': '*/*',
                'Connection':'close',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent':'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Referer': '',
                'Origin':'http://192.168.244.244',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.8'
                }
        data_dict={}
        post_auth_url="http://192.168.244.244/goform/PortalAuth"
        #先根据**kargs传入的值形成data字典{'192.168.0.33':[username,password]}
        for key,value in kargs.items():
            data_dict[key]=""
            #对data进行解析
            data_dict[key]={"webAuthUserName":"%s" %(value[0]),"webAuthUserPassword":"%s" %(value[1])}
        #循环
        postlist=[]
        for ip,url in self.post_list.items():
            header['Referer']=url
            postlist.append([ip,post_auth_url,header,data_dict[ip]])
        self.send_packet("post",*postlist)
        for i in postlist:
            #这里通过获取得到的值进行判断
            if self.post_response[i[0]].text.find("success") != -1:
                #说明成功了
                self.post_result[i[0]] = "Pass"
            else:
                self.post_result[i[0]] = "Fail"
            self.all_result[i[0]].append(self.post_response[i[0]].text)
            self.all_result[i[0]].append(self.post_result[i[0]])
            self.all_result[i[0]].append(data_dict[i[0]]['webAuthUserName'])
        self.savemsg()
    def send_packet(self,methods,*args):
        for ip,url,header,data in args:
            new_source = source.SourceAddressAdapter(ip) ;#选择网卡信息,即绑定源IP地址
            s.mount('http://', new_source)  #设置http请求与套接字绑定
            s.mount('https://', new_source)
            if not url.startswith("http"):
                url="http://"+url
            if methods == "get":
                self.get_response[ip]=s.get(url,headers=header)  
                #把请求结果存放到responses列表中
            else:
                self.post_response[ip]=s.post(url,headers=header,data=data)
                #把请求结果存放到responses列表中
            
    def savemsg(self):
        fd=open(self.filename,"a+")
        # fd.write("IP,domain,first_domain,result1,return_code,result2,username\n\n")
        for k,v in self.all_result.items():
            fd.write('%s,%s,%s,%s,"%s",%s,%s\n' %(k,v[0],v[1],v[2],v[3].replace('"',"'"),v[4],v[5]))
        fd.close()
if __name__ == "__main__":
    #第一步,生成请求的字典
    get_dict={}
    post_dict={}
    j=1
    for i in range(34,50):
        get_dict["192.168.1.%s" %(i)]="www.qq.com"
        post_dict["192.168.1.%s" %(i)]=["tenda%s" %(j),"tenda%s" %(j)]
        j=j+1
    print get_dict
    t=PotalAuth(**get_dict)
    t.config_macvlan()
    t.geturl(**get_dict)
    t.portal(**post_dict)
    t.del_macvlan()
