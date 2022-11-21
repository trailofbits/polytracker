#include <cassert>
#include <limits>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>


int read_write_connection_data(int conn) {

  ssize_t ret;
  char buffer[6];

  // Receive source taint via read, recv and recvfrom
 ret = read(conn, buffer, 2);
  assert(ret == 2);

  ret = recv(conn, &buffer[2], 2, 0);
  assert(ret == 2);

  ret = recvfrom(conn, &buffer[4], 2, 0, nullptr, nullptr);
  assert(ret == 2);

  // Split the echo reply across write and send
  ret = write(conn, &buffer[0], 3);
  assert(ret == 3);

  ret = send(conn, &buffer[3], 3, 0);
  assert(ret == 3);

  return 0;
}

int client(uint16_t port) {
  int ret;
  auto s = socket(PF_INET, SOCK_STREAM, 0);
  assert(s >= 0);

  sockaddr_in server_address {.sin_family = AF_INET, .sin_port = htons(port)};
  ret = inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);
  assert(ret == 1);

  ret = connect(s, reinterpret_cast<sockaddr const *>(&server_address), sizeof(server_address));
  assert(ret == 0);

  ret = read_write_connection_data(s);
  assert(ret == 0);

  ret = shutdown(s, SHUT_RDWR);
  assert(ret == 0);
  ret = close(s);
  assert(ret == 0);
  return 0;
}


int server(uint16_t port) {
  int ret;
  auto s = socket(PF_INET, SOCK_STREAM, 0);
  assert(s >= 0);

  const int enable = 1;
  ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
  assert(ret == 0);

  const int disable = 0;
  struct linger linger {.l_onoff = 0, .l_linger = 0};
  ret = setsockopt(s, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
  assert(ret == 0);

  sockaddr_in server_address {.sin_family = AF_INET, .sin_port = htons(port)};
  ret = inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);
  assert(ret == 1);

  ret = bind(s, reinterpret_cast<sockaddr const*>(&server_address), sizeof(server_address));
  assert(ret == 0);

  ret = listen(s, 5);
  assert(ret == 0);

  int client_socket = accept(s, nullptr, nullptr); // Don't care about client address
  assert(client_socket >= 0);

  ret = read_write_connection_data(client_socket);
  assert(ret == 0);

  // Close the client connection
  ret = shutdown(client_socket, SHUT_RDWR);
  assert(ret == 0);
  ret = close(client_socket);
  assert(ret == 0);

  // Close the listening socket
  ret = shutdown(s, SHUT_RDWR);
  assert(ret == 0);
  ret = close(s);
  assert(ret == 0);
  return 0;
}


int main(int argc, char* argv[]) {
  assert(argc == 4);

  std::string_view mode = argv[1];
  auto port = std::stoul(argv[2]);
  assert(port <= std::numeric_limits<uint16_t>::max());

  if (mode == "client") {
    return client(static_cast<uint16_t>(port));
  } else if (mode == "server") {
    return server(static_cast<uint16_t>(port));
  } else {
    return -1;
  }
}