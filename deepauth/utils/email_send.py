import smtplib
from email.mime.text import MIMEText
from email.header import Header

def send_mail(username, passwd, recvs, subject, content, mail_host='smtp.exmail.qq.com', port=465):
    '''
    发送邮件函数，默认使用163smtp
    :param username: 邮箱账号 xx@163.com
    :param passwd: 邮箱密码
    :param recv: 邮箱接收人地址，多个账号以逗号隔开
    :param title: 邮件标题
    :param content: 邮件内容
    :param mail_host: 邮箱服务器
    :param port: 端口号
    :return:
    '''
    msg = MIMEText(content, 'plain', 'utf-8')  # 邮件内容
    msg['Subject'] = Header(subject, 'utf-8')  # 邮件主题
    msg['From'] = username  # 发送者账号
    msg['To'] = recvs  # 接收者账号列表
    smtp = smtplib.SMTP(mail_host, port=port)  # 连接邮箱，传入邮箱地址，和端口号，smtp的端口号是25
    smtp.login(username, passwd)  # 发送者的邮箱账号，密码
    smtp.sendmail(username, recvs, msg.as_string())
    # 参数分别是发送者，接收者，第三个是把上面的发送邮件的内容变成字符串
    smtp.quit()  # 发送完毕后退出smtp
    print('email send success.')


# email_user = 'service@deepera.com'  # 发送者账号
# email_pwd = '4q8NjkBpsHPynYwt'  # 发送者密码
# email_recv = ['XXX@XXX.com', ]
# title = '测试邮件标题'
# content = '这里是邮件内容'
# host_mail ='smtp.exmail.qq.com'
# send_mail(email_user, email_pwd, email_recv, title, content, host_mail)

DEEPAUTH_EMAIL_VERIFICATION = {
    'server': 'smtp.exmail.qq.com',
    'username': 'service@deepera.com',
    'password': '4q8NjkBpsHPynYwt'
}
