import socket
import struct


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


def checkCorrect(packet):
    type, code, expectedSum, id, num = struct.unpack('bbHHh', packet[20:28])
    message = packet[28:len(packet)]
    header = struct.pack('bbHHh', type, code, 0, id, num)
    realSum = checkSum(str(header + message))
    return realSum == expectedSum


def createPacket(id, num, message):
    header = struct.pack('bbHHh', 0, 0, 0, id, num)
    packet = header + message
    check = checkSum(str(packet))
    header = struct.pack('bbHHh', 0, 0, check, id, num)
    return header + message


def listen():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(('', 14900))
    places = {}
    num = 1
    while 1:
        data, address = s.recvfrom(1508)
        packetNum = struct.unpack('H', data[26:28])[0]
        if not checkCorrect(data):
            print('Data corrupted')
            s.sendto(createPacket(0, packetNum, 'corrupted'.encode()), address)
            continue

        if len(data) == 28:
            item = places.pop(address[0])
            print(item[1])
            item[0].close()
            break
        elif address[0] not in places.keys():
            places[address[0]] = [open((data[28:len(data)]).decode(), 'wb'), 0]
            s.sendto(createPacket(0, packetNum, 'opened'.encode()), address)
        elif packetNum == places[address[0]][1] + 1:
            print('Correct')
            print(packetNum)
            places[address[0]][1] += 1
            places[address[0]][0].write(data[28:len(data)])
            s.sendto(createPacket(0, packetNum, 'correct'.encode()), address)

listen()
