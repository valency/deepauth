import smtplib
from email.header import Header
from email.mime.text import MIMEText


def send_mail(username, password, receivers, subject, content, host, port=465):
    """
    发送邮件
    :param username: 邮箱账号
    :param password: 邮箱密码
    :param receivers: 邮箱接收人地址，必须为数组
    :param subject: 邮件标题
    :param content: 邮件内容
    :param host: 邮箱服务器
    :param port: 端口号
    :return: 无
    """
    msg = MIMEText(content, 'plain', 'utf-8')  # 邮件内容
    msg['Subject'] = Header(subject, 'utf-8')  # 邮件主题
    msg['From'] = username  # 发送者账号
    msg['To'] = receivers  # 接收者账号列表
    smtp = smtplib.SMTP(host, port=port)  # 连接邮箱，传入邮箱地址，和端口号
    smtp.login(username, password)  # 发送者的邮箱账号，密码
    smtp.sendmail(username, receivers, msg.as_string())  # 参数分别是发送者，接收者，第三个是把上面的发送邮件的内容变成字符串
    smtp.quit()  # 发送完毕后退出 smtp