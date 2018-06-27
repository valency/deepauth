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
    msg = MIMEText(content, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = username
    msg['To'] = receiver
    smtp = smtplib.SMTP_SSL(host, port=port)
    smtp.login(username, password)
    resp = smtp.sendmail(username, receiver, msg.as_string())
    smtp.quit()
    return resp
