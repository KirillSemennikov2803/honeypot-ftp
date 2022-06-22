#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import time
import uuid

from twisted.cred.checkers import FilePasswordDB
from twisted.cred.portal import Portal
from twisted.internet import reactor, ssl
from twisted.protocols.ftp import FTPFactory, FTPRealm, FTP
from twisted.python import filepath


class FTPConfig:
    def __init__(self, *args, **kwargs):
        self.__version = "0.1.0"
        self.__appname = "not_honeypot_ftp"
        self.port = 21
        self.sslport = 990
        self.pubdir = "pub/"
        self.passwd_file = "passwd"
        self.ssl_cert_private = "keys/smtp.private.key"
        self.ssl_cert_public = "keys/smtp.public.key"
        self.elasticsearch = {"host": "127.0.0.1", "port": 9200, "index": "honeypot"}
        self.filename = "Ftp_honeypot_data.txt"


config = FTPConfig()


class MyFTPRealm(FTPRealm):
    def __init__(self, dir, anonymousRoot='/test'):
        super().__init__(anonymousRoot)
        self.userHome = filepath.FilePath(dir)

    def getHomeDirectory(self, avatarId):
        return self.userHome


class SimpleFtpProtocol(FTP):
    def __init__(self):
        self.session = str(
            uuid.uuid1()
        )
        self.my_own_host = None

    def connectionMade(self):
        self.__logInfo("connected", "", True)
        FTP.connectionMade(self)

    def connectionLost(self, reason):
        self.__logInfo("disconnected", "", True)
        FTP.connectionLost(self, reason)

    def lineReceived(self, line):
        self.__logInfo("command", line, True)
        FTP.lineReceived(self, line)

    def ftp_STOR(self, path):
        FTP.sendLine(self, b"125 Data connection already open, starting transfer")
        FTP.sendLine(self, b"226 Transfer Complete.")

    def ftp_DELE(self, path):
        FTP.sendLine(self, b"250 Requested File Action Completed OK")

    def ftp_RNFR(self, fromName):
        FTP.sendLine(self, b"350 Requested file action pending further information.")

    def ftp_RNTO(self, toName):
        FTP.sendLine(self, b"250 Requested File Action Completed OK")

    def ftp_MKD(self, path):
        FTP.sendLine(self, b"257 Folder created")

    def ftp_RMD(self, path):
        FTP.sendLine(self, b"250 Requested File Action Completed OK")

    def __logInfo(self, type, command, successful):
        try:
            self.my_own_host = self.transport.getHost()
        except AttributeError:
            pass

        data = {
            "module": "FTP",
            "@timestamp": int(time.time() * 1000),
            "sourceIPv4Address": str(self.transport.getPeer().host),
            "sourceTransportPort": self.transport.getPeer().port,
            "type": type,
            "command": command,
            "success": successful,
            "session": self.session,
        }
        if self.my_own_host:
            data["destinationIPv4Address"] = str(self.my_own_host.host)
            data["destinationTransportPort"] = self.my_own_host.port



try:
    factory = FTPFactory(
        Portal(MyFTPRealm(config.pubdir, )), [FilePasswordDB(config.passwd_file)]
    )
    factory.protocol = SimpleFtpProtocol
    reactor.listenTCP(config.port, factory)
    reactor.listenSSL(
        config.sslport,
        factory,
        ssl.DefaultOpenSSLContextFactory(config.ssl_cert_private, config.ssl_cert_public),
    )
    logging.info(
        "Server listening on Port %s (Plain) and on %s (SSL)."
        % (config.port, config.sslport)
    )
    reactor.run()
except Exception as e:
    logging.error(str(e))
    exit(-1)
logging.info("Server shutdown.")
