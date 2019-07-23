import re
str = 'TCP server 172.16.1.101:443 localserver 172.16.66.1:53710, idle 0:01:09, bytes 27575949, flags UIO'

result=re.match('(\w+)\s+\w+\s+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5})\s+\w+\s+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}),\s+[a-zA-Z]+\s(\d{1,2}:\d{1,2}:\d{1,2}),\s+[a-zA-Z]+\s+(\d+),\s+[a-zA-Z]+\s([a-zA-Z]+)',str).groups()

time=result[3].split(':')

print('{0:<15}{1}{2}'.format('protocol',':',result[0]))
print('{0:<15}{1}{2}'.format('server',':',result[1]))
print('{0:<15}{1}{2}'.format('localserver',':',result[2]))
print('{0:<15}{1}{2}{3}{4}{5}'.format('idle',':',time[0],'小时',time[1]+'分钟',time[2]+'秒'))
print('{0:<15}{1}{2}'.format('bytes',':',result[4]))
print('{0:<15}{1}{2}'.format('flags',':',result[5]))


