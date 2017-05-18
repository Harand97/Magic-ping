import struct
import socket


def checkSum(infString):
    sum = 0
    countTo = (len(infString) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = ord(infString[count + 1]) * 256 + ord(infString[count])
        sum += thisVal
        sum &= 0xffffffff
        count += 2
    if countTo < len(infString):
        sum += ord(infString[countTo])
        sum &= 0xffffffff
    sum = (sum >> 16) + sum & 0xffff
    sum += sum >> 16
    answer = ~sum
    answer &= 0xffff
    answer = answer >> 8 | (answer << 8 & 0xffff)
    return answer


def createPacket(id, num, message):
    header = struct.pack('bbHHh', 8, 0, 0, id, num)
    packet = header + message
    check = checkSum(str(packet))
    header = struct.pack('bbHHh', 8, 0, check, id, num)
    return header + message


def sendFile(filename, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(5)

    id = 4
    num = 0
    packet = createPacket(id, num, filename.encode())

    code = 0
    while True:
        try:
            if code == 0:
                s.sendto(packet, (addr, 1))
                code = 1
            data, address = s.recvfrom(1508)
            if struct.unpack('b', data[20:21])[0] != 0:
                continue
            if (data[28:len(data)]).decode() == 'opened':
                break
            if (data[28:len(data)]).decode() == 'corrupted':
                code = 0
                continue
        except socket.timeout:
            code = 0
            continue

    f = open(filename, 'rb')
    message = f.read(1472)
    all_len = 0
    while message:
        if num + 1 < 0xffff:
            num += 1
        else:
            num = 0
        all_len += len(message)
        packet = createPacket(id, num, message)
        code = 0
        while True:
            try:
                if code == 0:
                    s.sendto(packet, (addr, 1))
                    code = 1

                data, address = s.recvfrom(1508)
                if struct.unpack('b', data[20:21])[0] != 0:
                    continue
                if (data[28:len(data)]).decode() == 'correct':
                    break
                if (data[28:len(data)]).decode() == 'corrupted':
                    code = 0
                    continue
            except socket.timeout:
                code = 0
                continue
        message = f.read(1472)
        print(num)
    packet = createPacket(id, num, b'')
    s.sendto(packet, (addr, 1))


filename = input()
addr = input()
sendFile(filename, addr)
