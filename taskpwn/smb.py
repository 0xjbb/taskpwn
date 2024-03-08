
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.nmb import NetBIOSTimeout
from impacket.examples.secretsdump import RemoteOperations
from impacket.smb3structs import FILE_READ_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE, FILE_SHARE_READ


class TaskPwnSMB:
    def __init__(self, host, port, username, password):
        self.__target = host
        self.__port = 445
        self.__remote_ops = None
        self._smbv1 = False
        self._conn = ''
        self._is_admin = False


    def smb1_connection(self):
        pass
    def smb3_connection(self):
        try:
            self.__conn = SMBConnection()
        pass

    def connect(self):
        pass



    def is_admin(self):
        pass
