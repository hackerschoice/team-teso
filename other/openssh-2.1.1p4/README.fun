Enabling reverse fun
====================

Reverse fun was 'invented' to allow users outside firewalls (which deny
any incoming connects) or users behind masquerading routers to use ssh.
In december 1999 on the Chaos Congress we faced the problem that the whole
network was NATed and therefore nobody could connect to one of our
ssh-servers. Dream-team TESO solved this problem by using scut's excellent
'reverb' which mapped two active connections together and brought
the client into internal network. I was very impressed and half a year
after I patched OpenSSH to allow such things to happen without use of
'third-party'-software. :)

How it works
------------

When having reverse fun, the server (sshd) act's indeed as client and brings
a connect to the now-server 'ssh' outside the firewall. SSH-protocol
negotiation goes as normal then, and the user of ssh-client sees
no difference as if (s)he would do the connect normally.
Since the ssh-client acts as server until connect arrives,
it blocks the user's terminal until a person (or crond:) behind the
firewall initiates the connection.

Security
--------

During reverse fun, the server must authenticate itself using
the host-key as usual, so you can be sure the right connection arrived when
no warning-message is placed on the screen.
Since ssh-client runs setuid-root, reverse fun might be a danger (high-port
bindings etc.). I've written it just for fun, and you propably shouldn't
run this patched OpenSSH on production-machines.

IPv6 support is built in, but not tested.


Samples
-------

client:
    sshd -r foobar -p 7350 to connect to foobar:7350 where a client must listen
    
server:
    ssh -r -p 7350 to wait for incoming connects on port 7350


When you have other funny idea's how to turn world upside down
with programming tricks, contact me: krahmer@cs.uni-potsdam.de

-Sebastian
