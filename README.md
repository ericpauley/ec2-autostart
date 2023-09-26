# ec2-autostart
EC2 instances only accrue instance hours when they are turned on. We can take
advantage of this by shutting down instances when not in use and booting them on
demand through our VPN. Like socket activation, but for whole instances!

# `autostart`

`autostart` monitors for TCP SYN and ICMP (ping) packets on a Wireguard
interface. When it receives these, it checks if the IP belongs to a stopped EC2
instance in one of the AWS accounts specified in the config file, and if so
starts it.

Usage: 

    autostart [wg_interface] [mapping_json]
        wg_interface: Interface to listen on. E.g.: wg0
        mapping_json: Path to the JSON mapping config file. E.g.: /etc/autostart/mapping.json

Example: `autostart wg0 /etc/autostart/mapping.json`

## Instance tagging

`autostart` limits its search to EC2 instances that have a tag `autostart=true`
set.

## Permissions
`autostart` will automatically assume the IAM role of the VPN EC2 instance it is
executed on. 

### Under the same main AWS account as the VPN

1. To start instances under the same main AWS account the VPN EC2 instance is
running, you should assign a policy with at least the following permissions:
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
2. Add the corresponding configuration to the
   [`mapping.json`](autostart/mapping.json) file on your VPN EC2 instance
   (`Ec2InstanceMetadata` instructs `autostart` to use the IAM role directly
   attached to the VPN EC2 instance):
    ```json
            {
                "ipRange": "192.0.2.0/24",
                "arnRole": "Ec2InstanceMetadata"
            }
    ```

### Under other AWS accounts

To start EC2 instances into other AWS account(s) as well, you will need to do
the following for each new AWS account:

1. On the new AWS account, create an IAM policy with the following permissions:
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
    Note: do not restrict the `Resource` field with an ARN role, otherwise this will
    prevent us from assuming the corresponding role from the main AWS account.

2. On the new AWS account, create a new IAM role and attach to it the previously
   created IAM policy. Configure this new IAM role, so that the IAM role on your
   main account that is attached to your VPN EC2 isntance can assume this role
   on your new account: 
    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Statement1",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::<MAIN-ACCOUNT-ID>:role/<MAIN-ACCOUNT-IAM-VPN-ROLE>"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    ```
3. On your main AWS account under which your VPN EC2 instance is deployed, add a
   new IAM policy to the IAM role that is attached to your VPN EC2 instance, so
   that it can assume the IAM role created in your new account:
    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Statement1",
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole"
                ],
                "Resource": [
                    "arn:aws:iam::<NEW-ACCOUNT-ID>:role/<NEW-ACCOUNT-IAM-AUTOSTART-ROLE>"
                ]
            }
        ]
    }
    ```
4. Add the corresponding configurations for your new AWS account to the
   [`mapping.json`](autostart/mapping.json) file on your VPN EC2 instance:
    ```json
            {
                "ipRange": "203.0.113.0/24",
                "arnRole": "arn:aws:iam::<NEW-ACCOUNT-ID>:role/<NEW-ACCOUNT-IAM-AUTOSTART-ROLE>"
            }
    ```

## `autostart.service`

- Install the `autostart` binary on your VPN EC2 instance and create/edit
  [`mapping.json`](autostart/mapping.json) and
  [`autostart.service`](autostart/autostart.service)
    ```sh
    go build -o autostart autostart.go
    sudo mv autostart /usr/bin/autostart
    sudo chmod +x /usr/bin/autostart
    sudo nano /etc/autostart/mapping.json
    sudo nano /etc/systemd/system/autostart.service
    ```
- Enable and start the `autostart.service`, or if you just added a new AWS
  account reload and restart it:
    ```sh
    sudo systemctl enable autostart.service
    sudo systemctl start autostart.service
    ```
    or 
    ```sh
    sudo systemctl daemon-reload
    sudo systemctl restart autostart.service
    ```
- Test that a stopped instance (tagged with `autostart = true`)autostarts when
   you try to ssh into it through your VPN.

## `RST` suppression

TCP clients will automatically retry connections while the instance is booting,
but `connection refused` (TCP `RST`) packets can occur if the system starts but
the desired service is not yet started. To deal with this, `autostart`
automatically creates `iptables` rules that suppress `RST` packets for 30
seconds after booting each instance.


# `autostop`
`autostop` automatically shuts down an EC2 instance when there is no activity.
It is designed for instances that are primarily used for SSH (or VSCode over
SSH) and background tasks via `screen`.

Usage: 

    autostop [duration] [cmd]
        duration: Duration of inactivity before shutdown. E.g.: 10m
        cmd: Command to run to shutdown. E.g.: /usr/bin/systemctl poweroff

Example: `/usr/bin/autostop 10m /usr/bin/systemctl poweroff`

Easy install script (run as root):
```sh
curl -L "https://github.com/ericpauley/ec2-autostart/releases/latest/download/autostop-`uname -m`" -o /usr/bin/autostop
chmod +x /usr/bin/autostop
curl -L "https://github.com/ericpauley/ec2-autostart/releases/latest/download/autostop.service" -o /etc/systemd/system/autostop.service
systemctl enable autostop.service && systemctl start autostop.service
```

## Ending inactive ssh sessions

Most default `sshd` configurations will not end inactive sessions, such as if
you close your laptop without explicitly closing SSH or VSCode. The following
lines in `sshd_config` will end these sessions (after roughly 3*60=180 seconds):

```
ClientAliveInterval 60
ClientAliveCountMax 3
```

# Client configuration

Because EC2 instances take some time to boot (usually under 30s to receiving SSH
connections), SSH needs to be configured to wait longer before timing out. You
can set `ConnectTimeout 30` in for a host in `.ssh/config` on the client to
increase this timeout.
