/* packet_capture_benchmark.cpp
 * Benchmark Raw Socket, libpcap, and TPACKETv3
 * Build: g++ -O3 -std=c++17 -lpcap -o capture_bench packet_capture_benchmark.cpp
 * Run:   sudo ./capture_bench --mode raw|pcap|tpacket3
 */
/* testing the git repos working tree stash test12121212*/
#include <iostream>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <vector>
#include <poll.h>
#include <sys/mman.h>

constexpr int SNAPLEN = 65536;
constexpr int DURATION = 100; // seconds
constexpr const char* INTERFACE = "enp0s3"; // Change this to your active interface

void benchmark_raw_socket() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Raw socket failed");
        return;
    }

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sock);
        return;
    }

    struct sockaddr_ll sll = {};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return;
    }

    char buffer[SNAPLEN];
    uint64_t packets = 0;
    auto start = std::chrono::steady_clock::now();

    while (true) {
        int n = recv(sock, buffer, sizeof(buffer), 0);
        if (n > 0) packets++;

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - start).count() > DURATION) break;
    }

    std::cout << "[RAW] Packets: " << packets << ", Pkts/sec: " << (packets / DURATION) << std::endl;
    close(sock);
}

void benchmark_libpcap() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(INTERFACE, SNAPLEN, 1, 1, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    uint64_t packets = 0;
    auto start = std::chrono::steady_clock::now();

    while (true) {
        int res = pcap_next_ex(handle, &header, &data);
        if (res == 1) packets++;

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - start).count() > DURATION) break;
    }

    std::cout << "[PCAP] Packets: " << packets << ", Pkts/sec: " << (packets / DURATION) << std::endl;
    pcap_close(handle);
}

void benchmark_tpacket3() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return;
    }

    int ver = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
        perror("setsockopt PACKET_VERSION");
        close(sock);
        return;
    }

    const int block_size = 1 << 22; // 4MB
    const int block_nr = 64;
    const int frame_size = 1 << 11; // 2KB
    const int frame_nr = (block_size / frame_size) * block_nr;

    struct tpacket_req3 req = {};
    req.tp_block_size = block_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_size = frame_size;
    req.tp_frame_nr = frame_nr;
    req.tp_retire_blk_tov = 60; // timeout in ms

    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        perror("setsockopt PACKET_RX_RING");
        close(sock);
        return;
    }

    size_t mmap_size = req.tp_block_size * req.tp_block_nr;
    void* mmap_ptr = mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if (mmap_ptr == MAP_FAILED) {
        perror("mmap");
        close(sock);
        return;
    }

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        munmap(mmap_ptr, mmap_size);
        close(sock);
        return;
    }

    struct sockaddr_ll sll = {};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        munmap(mmap_ptr, mmap_size);
        close(sock);
        return;
    }

    uint64_t packets = 0;
    auto start = std::chrono::steady_clock::now();
    uint8_t* base = static_cast<uint8_t*>(mmap_ptr);

    struct pollfd pfd = {.fd = sock, .events = POLLIN};

    while (true) {
        int poll_res = poll(&pfd, 1, 1000);
        if (poll_res <= 0) continue;

        for (int i = 0; i < req.tp_block_nr; ++i) {
            auto blk = reinterpret_cast<tpacket_block_desc*>(base + (i * req.tp_block_size));
            if (!(blk->hdr.bh1.block_status & TP_STATUS_USER)) continue;

            uint32_t num_pkts = blk->hdr.bh1.num_pkts;
            auto hdr = reinterpret_cast<tpacket3_hdr*>((uint8_t*)blk + blk->hdr.bh1.offset_to_first_pkt);
            for (uint32_t j = 0; j < num_pkts; ++j) {
                packets++;
                hdr = (tpacket3_hdr*)((uint8_t*)hdr + hdr->tp_next_offset);
            }

            blk->hdr.bh1.block_status = TP_STATUS_KERNEL;
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - start).count() > DURATION) break;
    }

    std::cout << "[TPACKETv3] Packets: " << packets << ", Pkts/sec: " << (packets / DURATION) << std::endl;
    munmap(mmap_ptr, mmap_size);
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc < 3 || std::string(argv[1]) != "--mode") {
        std::cerr << "Usage: sudo ./capture_bench --mode raw|pcap|tpacket3" << std::endl;
        return 1;
    }

    std::string mode = argv[2];
    if (mode == "raw") {
        benchmark_raw_socket();
    } else if (mode == "pcap") {
        benchmark_libpcap();
    } else if (mode == "tpacket3") {
        benchmark_tpacket3();
    } else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        return 1;
    }

    return 0;
}
