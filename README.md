# ec2-autostart
EC2 instances only accrue instance hours when they are turned on. We can take advantage of this by shutting down instances when not in use and booting them on demand through our VPN. Like socket activation, but for whole instances!

# `autostart`
`autostart` monitors for TCP SYN and ICMP (ping) packets on a Wireguard interface. When it receives these, it checks if the IP belongs to a stopped EC2 instance, and if so starts it.

Usage: `autostart [wg0]`

## Instance tagging

`autostart` limits its search to EC2 instances that have a tag `autostart=true` set.

## Permissions
`autostart` will automatically assume the IAM role of the EC2 instance. You should assign a policy with at least the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:StartInstances",
                "ec2:DescribeInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

## `RST` suppression

TCP clients will automatically retry connections while the instance is booting, but `connection refused` (TCP `RST`) packets can occur if the system starts but the desired service is not yet started. To deal with this, `autostart` automatically creates `iptables` rules that suppress `RST` packets for 30 seconds after booting each instance.


# `autostop`
`autostop` automatically shuts down an EC2 instance when there is no activity. It is designed for instances that are primarily used for SSH (or VSCode over SSH) and background tasks via `screen`.

Usage: 

    autostop [duration] [cmd]
        duration: Duration of inactivity before shutdown. E.g.: 10m
        cmd: Command to run to shutdown. E.g.: /usr/bin/systemctl poweroff

Example: `/usr/bin/autostop 10m /usr/bin/systemctl poweroff`

## Ending inactive ssh sessions

Most default `sshd` configurations will not end inactive sessions, such as if you close your laptop without explicitly closing SSH or VSCode. The following lines in `sshd_config` will end these sessions (after roughly 3*60=180 seconds):

```
ClientAliveInterval 60
ClientAliveCountMax 3
```

# Client configuration

Because EC2 instances take some time to boot (usually under 30s to receiving SSH connections), SSH needs to be configured to wait longer before timing out. You can set `ConnectTimeout 30` in for a host in `.ssh/config` on the client to increase this timeout.