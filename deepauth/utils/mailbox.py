import smtplib
from email.header import Header
from email.mime.text import MIMEText


def send_mail(host, port, username, password, receiver, subject='Test', content='This is a test email.'):
    """
    发送邮件
    :param username: 邮箱账号
    :param password: 邮箱密码
    :param receiver: 收件人地址
    :param subject: 邮件标题
    :param content: 邮件内容
    :param host: 邮箱服务器
    :param port: 端口号
    :return: 邮件发送情况，详情请参考 smtp.sendmail()
    """
    msg = MIMEText(content, 'plain', 'utf-8')  # 邮件内容
    msg['Subject'] = Header(subject, 'utf-8')  # 邮件主题
    msg['From'] = username  # 发送者账号
    msg['To'] = receiver  # 接收者账号
    smtp = smtplib.SMTP_SSL(host, port=port)  # 连接邮箱，传入邮箱地址，和端口号
    smtp.login(username, password)  # 发送者的邮箱账号，密码
    resp = smtp.sendmail(username, receiver, msg.as_string())  # 参数分别是发送者，接收者，第三个是把上面的发送邮件的内容变成字符串
    smtp.quit()  # 发送完毕后退出 smtp
    return resp
