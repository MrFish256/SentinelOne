from datetime import datetime
import s1
import smtplib, ssl
from config import COGNITO_BRAIN, S1_URL

# This SMTP-configuration should be adjusted to your needs.
smtp_host = "127.0.0.1"
smtp_port = 25
smtp_from = "user@localhost.localdomain"
smtp_to = "user@localhost"
smtp_message_template = """Hello,

This is an automated message. 

One or more SentinelOne agents have been automatically blocked, because the hosts exceed the auto-block Threat and Certainty 
minimum threshold. 

Amount of blocked S1 agents: {}

The following hosts were blocked:
{}

Vectra URL: {}
SentinelOne URL: {}

Thank you.
"""

def send_mail(hosts_blocked):
    message_content = ""

    for host in hosts_blocked:
        host_ip_address = host['last_source']
        host_name = host['name']

        message_content += "- " + host_ip_address
        message_content += " - host [" + host_name + "]"
        message_content += " - threat/certainty [{}/{}] ".format(host['threat'], host['certainty'])
        message_content += " - severity [{}] ".format(host['severity'])
        message_content += " - URL [{}] ".format(host['host_url'])
        message_content += "\n"

    #context = ssl._create_unverified_context()
    server = smtplib.SMTP(smtp_host, smtp_port)
    server.ehlo()
    #server.starttls(context)
    server.sendmail(smtp_from, smtp_to, smtp_message_template.format(str(len(hosts_blocked)),
                                                                     message_content,
                                                                     COGNITO_BRAIN,
                                                                     S1_URL))
    print('Sending email notification to {} for {} blocked hosts'.format(smtp_to, str(len(hosts_blocked))))

# Monkey patching s1.py.
# This custom impl. will send an email using Sendmail to inform about blocked hosts.
def auto_block_s1_agents_sendmail(hosts, tc_autoblock, blocktags, monitor_mode_enabled):
    # Supplied hosts will be auto-blocked, if TC autoblock criteria are met.
    hosts_blocked = []

    for hostid in hosts.keys():
        host_ip_address = hosts[hostid]['last_source']
        host_threat = hosts[hostid]['threat']
        host_certainty = hosts[hostid]['certainty']

        host_threat_minimum = tc_autoblock[0]
        host_certainty_minimum = tc_autoblock[1]

        if host_threat >= host_threat_minimum and host_certainty >= host_certainty_minimum:
            # We consider the host as already blocked, when it has the provided BLOCKTAG as host tag.
            if blocktags[0] in hosts[hostid]['tags']:
                print('hosts_id:{} already auto-blocked and skipped'.format(host_ip_address))
            else:
               s1.add_host_note(hostid, 'Auto-blocking S1 agent {} - threat/certainty [{}/{}] => auto-block [{}/{}]'.format(host_ip_address, host_threat, host_certainty, host_threat_minimum, host_certainty_minimum))
               s1.VC.set_host_tags(host_id=hostid, tags=blocktags, append=True)
               hosts_blocked.append(hosts[hostid])

    # Send email for blocked hosts..
    if len(hosts_blocked) > 0:
        send_mail(hosts_blocked)

    return hosts_blocked

# Override original method with our custom impl.
s1.auto_block_s1_agents = auto_block_s1_agents_sendmail

if __name__ == '__main__':
    s1.main()
