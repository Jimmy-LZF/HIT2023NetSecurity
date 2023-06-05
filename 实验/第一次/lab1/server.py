import socket
import os

# 创建TCP socket对象
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 设置socket地址重用选项
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# 绑定IP地址和端口号
# TODO// server ip
server_socket.bind(("192.168.253.130", 4444))

# 开始监听连接请求
server_socket.listen()

print("Server is listening on port 8888...")

while True:
    # 等待客户端连接
    client_socket, client_address = server_socket.accept()
    print(f"Client {client_address[0]}:{client_address[1]} connected")
    # 接收客户端请求
    request = client_socket.recv(1024).decode()

    # 根据请求类型处理请求
    if request == "upload":
        client_socket.send("file name and size have been received.".encode())
        # 接收客户端传来的文件名和文件大小
        filename, filesize = client_socket.recv(1024).decode().split("|")
        if(len(filesize)<10):
                pass
        else:
            for index in range(len(filesize)):
                if(filesize[index]=='i'):
                    filesize=filesize[0:index]
                    break       
        filesize = int(filesize)

        # 打开文件，准备写入
        with open(filename, "wb") as f:
            # 从客户端接收数据并写入文件
            data = client_socket.recv(1024)
            total_recv_size = len(data)
            f.write(data)
            while total_recv_size < filesize:
                data = client_socket.recv(1024)
                total_recv_size += len(data)
                f.write(data)
        print(
            f"{filename} has been received from {client_address[0]}:{client_address[1]}"
        )
    elif request == "download":
        # 获取服务端当前目录下的文件列表
        file_list = os.listdir(".")
        # 将文件列表发送给客户端
        client_socket.send(str(file_list).encode())
        # 接收客户端请求的文件名
        filename = client_socket.recv(1024).decode()

        # 如果文件存在，打开文件并发送给客户端
        if os.path.exists(filename):
            filesize = os.path.getsize(filename)
            #print(filesize)
            #print('\n')
            client_socket.send(f"{filename}|{filesize}".encode())
            with open(filename, "rb") as f:
                data = f.read(1024)
                while data:
                    client_socket.send(data)
                    data = f.read(1024)
            print(
                f"{filename} has been sent to {client_address[0]}:{client_address[1]}"
            )
        else:
            client_socket.send(f"File {filename} does not exist.".encode())
    elif request == "close":  # it seems that this statement will never be executed.
        print(f"Client {client_address[0]}:{client_address[1]} disconnected")
        client_socket.close()