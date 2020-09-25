import bluepy.btle as btle
from Cryptodome.Cipher import AES
from . import util


class SessionDelegate(btle.DefaultDelegate):
    def __init__(self, session):
        btle.DefaultDelegate.__init__(self)
        self.session = session
        self.data = None

    def handleNotification(self, cHandle, data):
        if self.data is not None:
            return

        print("Receiving response: " + data.hex())

        data = self.session.decrypt(data)
        print("Decrypted response: " + data.hex())
        self.session._validate_response(data)
        self.data = data


class Session:
    cipher_encrypt = None
    cipher_decrypt = None

    def __init__(self, peripheral):
        self.peripheral = peripheral

    def set_write(self, write_characteristic):
        self.write_characteristic = write_characteristic

    def set_read(self, r):
        self.read_characteristic = r
        # set up client Char Configuration 
        # 32 is INDICATE property.  This was traced in nRF Connect.
        if r.properties & 32 != 0:
            for d in r.getDescriptors():
                # 0x0200 is enable indication
                # https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/bluetooth/BluetoothGattDescriptor.java
                res = d.write(b'\x02\x00', withResponse=True)
                print(f"Nofication enabled {d.uuid} {r.uuid}")
        # 20 is 0b10100 NOTIFY and READ properties
        if r.properties & 20 != 0:
            for d in r.getDescriptors():
                # 0x0100 is enable notification.  See link above.
                res = d.write(b'\x01\x00', withResponse=True)
                print(f"Nofication enabled {d.uuid} {r.uuid}")

    def set_key(self, key: bytes):
        self.cipher_encrypt = AES.new(key, AES.MODE_CBC, iv=bytes(0x10))
        self.cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=bytes(0x10))

    def decrypt(self, data: bytearray):
        if self.cipher_decrypt is not None:
            cipherText = data[0x00:0x10]
            plainText = self.cipher_decrypt.decrypt(cipherText)
            if type(data) is not bytearray:
                data = bytearray(data)
            util._copy(data, plainText)

        return data

    def build_command(self, opcode: int):
        cmd = bytearray(0x12)
        cmd[0x00] = 0xee
        cmd[0x01] = opcode
        cmd[0x10] = 0x02
        return cmd

    def _write_checksum(self, command: bytearray):
        checksum = util._simple_checksum(command)
        command[0x03] = checksum

    def _validate_response(self, response: bytearray):
        print("Response simple checksum: " + str(util._simple_checksum(response)))
        if util._simple_checksum(response) != 0:
            raise Exception("Simple checksum mismatch")

        if response[0x00] != 0xbb and response[0x00] != 0xaa:
            raise Exception("Incorrect flag in response")

    def _write(self, command: bytearray):
        print("Writing command: " + command.hex())

        # NOTE: The last two bytes are not encrypted
        # General idea seems to be that if the last byte
        # of the command indicates an offline key offset (is non-zero),
        # the command is "secure" and encrypted with the offline key
        if self.cipher_encrypt is not None:
            plainText = command[0x00:0x10]
            cipherText = self.cipher_encrypt.encrypt(plainText)
            util._copy(command, cipherText)

        print("Encrypted command: " + command.hex())

        delegate = SessionDelegate(self)

        self.peripheral.withDelegate(delegate)
        self.write_characteristic.write(command, True)
        if delegate.data is None and \
                self.peripheral.waitForNotifications(20) is False:
            raise Exception("Notification timed out")

        return delegate.data

    def execute(self, command: bytearray):
        self._write_checksum(command)
        return self._write(command)


class SecureSession(Session):

    def __init__(self, peripheral, key_index):
        super().__init__(peripheral)
        self.key_index = key_index

    def set_key(self, key: bytes):
        self.cipher_encrypt = AES.new(key, AES.MODE_ECB)
        self.cipher_decrypt = AES.new(key, AES.MODE_ECB)

    def build_command(self, opcode: int):
        cmd = bytearray(0x12)
        cmd[0x00] = opcode
        cmd[0x10] = 0x0f
        cmd[0x11] = self.key_index
        return cmd

    def _write_checksum(self, command: bytearray):
        checksum = util._security_checksum(command)
        checksum_bytes = checksum.to_bytes(4, byteorder='little', signed=False)
        util._copy(command, checksum_bytes, destLocation=0x0c)

    def _validate_response(self, data: bytes):
        print("Response security checksum: " + str(util._security_checksum(data)))
        response_checksum = int.from_bytes(data[0x0c:0x10], byteorder='little', signed=False)
        print("Response message checksum: " + str(response_checksum))
        if util._security_checksum(data) != response_checksum:
            raise Exception("Security checksum mismatch")
